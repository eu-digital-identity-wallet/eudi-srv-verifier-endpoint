/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import COSE.AlgorithmID
import COSE.OneKey
import arrow.core.*
import arrow.core.raise.*
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist.StatusListTokenValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Iso180135
import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mdocauth.DeviceAuthentication
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.MSO
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toStdlibInstant
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import kotlin.time.Instant

enum class ValidityInfoShouldBe {
    NotExpired,
    NotExpiredIfPresent,
    Ignored,
}

enum class IssuerSignedItemsShouldBe {
    Verified,
    Ignored,
}

sealed interface DocumentError {
    data object MissingValidityInfo : DocumentError
    data class ExpiredValidityInfo(val validFrom: Instant, val validTo: Instant) : DocumentError
    data object IssuerKeyIsNotEC : DocumentError
    data object InvalidIssuerSignature : DocumentError
    data class X5CNotTrusted(val cause: String?) : DocumentError
    data object DocumentTypeNotMatching : DocumentError
    data object InvalidIssuerSignedItems : DocumentError
    data object NoMatchingX5CShouldBe : DocumentError
    data object DocumentHasBeenRevoked : DocumentError
    data object MissingDeviceSigned : DocumentError
    data class DeviceKeyNotAuthorizedToSignItems(val unauthorized: Map<NameSpace, NonEmptyList<DataElementIdentifier>>) : DocumentError
    class DevicePublicKeyCannotBeParsed(val cause: Throwable) : DocumentError
    class DeviceKeyIsNotEC(val cause: Throwable) : DocumentError
    data object InvalidDeviceSignature : DocumentError
}

private val log = LoggerFactory.getLogger(DocumentValidator::class.java)

class DocumentValidator(
    private val clock: Clock = Clock.System,
    private val validityInfoShouldBe: ValidityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
    private val issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
    private val provideTrustSource: ProvideTrustSource,
    private val statusListTokenValidator: StatusListTokenValidator?,
) {
    suspend fun ensureValid(
        document: MDoc,
        transactionId: TransactionId? = null,
        handoverInfo: HandoverInfo? = null,
    ): EitherNel<DocumentError, MDoc> =
        either {
            document.decodeMso()

            val x5CShouldBe = ensureMatchingX5CShouldBe(document, provideTrustSource)

            val issuerChain = ensureTrustedChain(document, x5CShouldBe)
            zipOrAccumulate(
                { ensureNotExpiredValidityInfo(document, clock, validityInfoShouldBe) },
                { ensureMatchingDocumentType(document) },
                { ensureDigestsOfIssuerSignedItems(document, issuerSignedItemsShouldBe) },
                {
                    ensureValidIssuerSignature(document, issuerChain, x5CShouldBe.caCertificates())
                        .also { log.info("IssuerSigned validation succeeded") }
                },
                { ensureNotRevoked(document, statusListTokenValidator, transactionId) },
            ) { _, _, _, _, _ -> document }
            if (null != handoverInfo) {
                ensureValidDeviceSigned(document, handoverInfo)
                    .also { log.info("DeviceSigned validation succeeded") }
            }

            document
        }
}

private fun Raise<DocumentError>.ensureNotExpiredValidityInfo(
    document: MDoc,
    clock: Clock,
    validityInfoShouldBe: ValidityInfoShouldBe,
) {
    fun ValidityInfo.notExpired() {
        val validFrom = validFrom.value.toStdlibInstant()
        val validTo = validUntil.value.toStdlibInstant()
        val now = clock.now()
        ensure(now in validFrom..validTo) {
            DocumentError.ExpiredValidityInfo(validFrom, validTo)
        }
    }

    val validityInfo = document.MSO?.validityInfo
    when (validityInfoShouldBe) {
        ValidityInfoShouldBe.NotExpired ->
            ensureNotNull(validityInfo) { DocumentError.MissingValidityInfo }.notExpired()

        ValidityInfoShouldBe.NotExpiredIfPresent -> validityInfo?.notExpired()
        ValidityInfoShouldBe.Ignored -> Unit
    }
}

private fun Raise<DocumentError.DocumentTypeNotMatching>.ensureMatchingDocumentType(document: MDoc) =
    ensure(document.verifyDocType()) {
        DocumentError.DocumentTypeNotMatching
    }

private fun Raise<DocumentError>.ensureValidIssuerSignature(
    document: MDoc,
    chain: NonEmptyList<X509Certificate>,
    caCertificates: List<X509Certificate>,
) {
    val issuerKeyInfo = cryptoProviderKeyInfo(chain, caCertificates)
    val issuerCryptoProvider = SimpleCOSECryptoProvider(listOf(issuerKeyInfo))
    ensure(document.verifySignature(issuerCryptoProvider, issuerKeyInfo.keyID)) {
        DocumentError.InvalidIssuerSignature
    }
}

private const val ISSUER_KEY_ID = "ISSUER_KEY_ID"
private fun Raise<DocumentError.IssuerKeyIsNotEC>.cryptoProviderKeyInfo(
    chain: NonEmptyList<X509Certificate>,
    caCertificates: List<X509Certificate>,
): COSECryptoProviderKeyInfo {
    val issuerECKey = ensureIssuerKeyIsEC(chain.head)
    return COSECryptoProviderKeyInfo(
        keyID = ISSUER_KEY_ID,
        algorithmID = issuerECKey.coseAlgorithmID,
        publicKey = issuerECKey.toECPublicKey(),
        privateKey = null,
        x5Chain = chain,
        trustedRootCAs = caCertificates,
    )
}

private fun Raise<DocumentError.IssuerKeyIsNotEC>.ensureIssuerKeyIsEC(issuerCert: X509Certificate): ECKey =
    try {
        ECKey.parse(issuerCert)
    } catch (e: Exception) {
        raise(DocumentError.IssuerKeyIsNotEC)
    }

private val ECKey.coseAlgorithmID: AlgorithmID
    get() =
        when (curve) {
            Curve.P_256 -> AlgorithmID.ECDSA_256
            Curve.P_384 -> AlgorithmID.ECDSA_384
            Curve.P_521 -> AlgorithmID.ECDSA_512
            else -> error("Unsupported ECKey Curve '$curve'")
        }

private fun Raise<DocumentError.InvalidIssuerSignedItems>.ensureDigestsOfIssuerSignedItems(
    document: MDoc,
    issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe,
) {
    if (issuerSignedItemsShouldBe == IssuerSignedItemsShouldBe.Verified) {
        ensure(document.verifyIssuerSignedItems()) { DocumentError.InvalidIssuerSignedItems }
    }
}

private fun Raise<Nel<DocumentError.X5CNotTrusted>>.ensureTrustedChain(
    document: MDoc,
    x5CShouldBe: X5CShouldBe,
): NonEmptyList<X509Certificate> =
    either {
        val chain = ensureContainsChain(document)
        ensureValidChain(chain, x5CShouldBe)
    }.toEitherNel().bind()

private fun Raise<DocumentError.X5CNotTrusted>.ensureContainsChain(
    document: MDoc,
): Nel<X509Certificate> {
    val issuerAuth =
        ensureNotNull(document.issuerSigned.issuerAuth) {
            DocumentError.X5CNotTrusted("Missing issuerAuth")
        }
    val chain =
        run {
            val x5c = ensureNotNull(issuerAuth.x5Chain) { DocumentError.X5CNotTrusted("Missing x5Chain") }
            val factory: CertificateFactory = CertificateFactory.getInstance("X.509")
            factory.generateCertificates(x5c.inputStream()).mapNotNull { it as? X509Certificate }.toNonEmptyListOrNull()
        }

    return ensureNotNull(chain) {
        DocumentError.X5CNotTrusted("Empty chain")
    }
}

private fun Raise<DocumentError.X5CNotTrusted>.ensureValidChain(
    chain: NonEmptyList<X509Certificate>,
    x5CShouldBe: X5CShouldBe,
): Nel<X509Certificate> {
    val x5cValidator = X5CValidator(x5CShouldBe)
    val validChain = x5cValidator.ensureTrusted(chain).mapLeft { exception ->
        DocumentError.X5CNotTrusted(exception.message)
    }
    return validChain.bind()
}

private suspend fun Raise<Nel<DocumentError.NoMatchingX5CShouldBe>>.ensureMatchingX5CShouldBe(
    document: MDoc,
    trustSourceProvider: ProvideTrustSource,
): X5CShouldBe = trustSourceProvider(document.docType.value) ?: raise(DocumentError.NoMatchingX5CShouldBe.nel())

private suspend fun Raise<DocumentError.DocumentHasBeenRevoked>.ensureNotRevoked(
    document: MDoc,
    statusListTokenValidator: StatusListTokenValidator?,
    transactionId: TransactionId?,
) {
    if (null != statusListTokenValidator) {
        catch({
            statusListTokenValidator.validate(document, transactionId)
        }) {
            raise(DocumentError.DocumentHasBeenRevoked)
        }
    }
}

private fun Raise<Nel<DocumentError>>.ensureValidDeviceSigned(document: MDoc, handoverInfo: HandoverInfo): MDoc {
    val mso = checkNotNull(document.MSO)

    val deviceSigned = ensureNotNull(document.deviceSigned) { DocumentError.MissingDeviceSigned.nel() }
    val nameSpaces = run {
        val decoded = cbor.decodeFromByteArray<MapElement>(deviceSigned.nameSpaces.value)
        decoded.toDeviceNameSpaces()
    }

    return zipOrAccumulate(
        { ensureValidKeyAuthorizations(mso, nameSpaces) },
        { ensureValidDeviceAuthentication(document, handoverInfo) },
    ) { _, _ -> document }
}

private fun Raise<DocumentError.DeviceKeyNotAuthorizedToSignItems>.ensureValidKeyAuthorizations(mso: MSO, nameSpaces: DeviceNameSpaces) {
    if (nameSpaces.isNotEmpty()) {
        val keyAuthorizations = mso.deviceKeyInfo.keyAuthorizations?.toKeyAuthorizations()
        ensureNotNull(keyAuthorizations) {
            DocumentError.DeviceKeyNotAuthorizedToSignItems(
                nameSpaces.mapValues { (_, dataElements) -> dataElements.items.map { it.identifier } },
            )
        }
        val fullyAuthorizedNameSpaces = keyAuthorizations.nameSpaces.orEmpty()
        val authorizedDataElementsPerNameSpace = keyAuthorizations.dataElements?.value.orEmpty()

        val unauthorized = buildMap {
            nameSpaces.forEach { (nameSpace, dataElements) ->
                dataElements
                    .items
                    .filter {
                            (identifier, _) ->
                        nameSpace !in fullyAuthorizedNameSpaces || identifier !in authorizedDataElementsPerNameSpace[nameSpace].orEmpty()
                    }
                    .map { it.identifier }
                    .toNonEmptyListOrNull()
                    ?.let { put(nameSpace, it) }
            }
        }
        ensure(unauthorized.isEmpty()) {
            DocumentError.DeviceKeyNotAuthorizedToSignItems(unauthorized)
        }
    }
}

private fun DeviceKeyInfo.cryptoProviderKeyInfo(): Either<DocumentError, COSECryptoProviderKeyInfo> =
    either {
        val publicKey = catch({
            val oneKey = OneKey(CBORObject.DecodeFromBytes(deviceKey.toCBOR()))
            oneKey.AsPublicKey()
        }) { raise(DocumentError.DevicePublicKeyCannotBeParsed(it)) }

        val ecKey = catch({
            val ecPublicKey = publicKey as ECPublicKey
            ECKey.Builder(Curve.forECParameterSpec(ecPublicKey.params), ecPublicKey).build()
        }) { raise(DocumentError.DeviceKeyIsNotEC(it)) }

        COSECryptoProviderKeyInfo(keyID = "DEVICE_KEY_ID", algorithmID = ecKey.coseAlgorithmID, publicKey = publicKey)
    }

private fun Raise<DocumentError>.ensureValidDeviceAuthentication(document: MDoc, handoverInfo: HandoverInfo) {
    val mso = checkNotNull(document.MSO)
    val deviceKeyCryptoProviderKeyInfo = mso.deviceKeyInfo.cryptoProviderKeyInfo().bind()

    val deviceSigned = checkNotNull(document.deviceSigned)
    val handover = handoverInfo.toHandover()
    val sessionTranscript = SessionTranscript(deviceEngagementBytes = null, eReaderKeyBytes = null, handover)
    val deviceAuthentication = DeviceAuthentication(sessionTranscript.toDataElement(), mso.docType.value, deviceSigned.nameSpaces)

    ensure(
        document.verifyDeviceSignature(
            deviceAuthentication,
            SimpleCOSECryptoProvider(listOf(deviceKeyCryptoProviderKeyInfo)),
            deviceKeyCryptoProviderKeyInfo.keyID,
        ),
    ) {
        DocumentError.InvalidDeviceSignature
    }
}

private typealias AuthorizedNameSpaces = NonEmptyList<NameSpace>

private fun ListElement.toAuthorizedNameSpaces(): AuthorizedNameSpaces =
    checkNotNull(value.map { (it as StringElement).value }.toNonEmptyListOrNull())

private typealias DataElementsArray = NonEmptyList<DataElementIdentifier>

private fun ListElement.toDataElementsArray(): DataElementsArray =
    checkNotNull(value.map { (it as StringElement).value }.toNonEmptyListOrNull())

@JvmInline
private value class AuthorizedDataElements(val value: Map<NameSpace, DataElementsArray>) {
    init {
        require(value.isNotEmpty()) { "AuthorizedDataElements must contain at least one NameSpace" }
        require(value.values.all { it.distinct().size == it.size }) {
            "DataElementsArray must not contain duplicate DataElementIdentifiers in a NameSpace"
        }
    }
}

private fun MapElement.toAuthorizedDataElements(): AuthorizedDataElements =
    buildMap {
        value.forEach { (nameSpace, dataElements) ->
            put(nameSpace.str, (dataElements as ListElement).toDataElementsArray())
        }
    }.let { AuthorizedDataElements(it) }

private data class KeyAuthorizations(val nameSpaces: AuthorizedNameSpaces?, val dataElements: AuthorizedDataElements?) {
    init {
        require(null != nameSpaces || null != dataElements) {
            "KeyAuthorizations must contain either AuthorizedNameSpaces or AuthorizedDataElements"
        }
        if (null != nameSpaces && null != dataElements) {
            val commonNameSpaces = nameSpaces.toSet().intersect(dataElements.value.keys)
            require(commonNameSpaces.isEmpty()) {
                "NameSpaces included in AuthorizedNameSpaces must not be included in AuthorizedDataElements. " +
                    "Non-compliant NameSpaces: ${commonNameSpaces.joinToString()}"
            }
        }
    }
}

private fun MapElement.toKeyAuthorizations(): KeyAuthorizations {
    val nameSpaces = value[MapKey(Iso180135.KEY_AUTHORIZATIONS_NAMESPACES)]?.let {
        (it as ListElement).toAuthorizedNameSpaces()
    }
    val dataElements = value[MapKey(Iso180135.KEY_AUTHORIZATIONS_DATA_ELEMENTS)]?.let {
        (it as MapElement).toAuthorizedDataElements()
    }
    return KeyAuthorizations(nameSpaces, dataElements)
}

private typealias DeviceNameSpaces = Map<NameSpace, DeviceSignedItems>

private fun MapElement.toDeviceNameSpaces(): DeviceNameSpaces =
    buildMap {
        value.forEach { (nameSpace, deviceSignedItems) ->
            put(nameSpace.str, (deviceSignedItems as MapElement).toDeviceSignedItems())
        }
    }

@JvmInline
private value class DeviceSignedItems(val items: NonEmptyList<DeviceSignedItem>) {
    init {
        val identifiers = items.map { it.identifier }
        require(identifiers.distinct().size == identifiers.size) { "DeviceSignedItems identifiers must be unique" }
    }
}

private fun MapElement.toDeviceSignedItems(): DeviceSignedItems =
    value.map { (identifier, value) -> DeviceSignedItem(identifier.str, value) }
        .toNonEmptyListOrNull()
        .let { DeviceSignedItems(checkNotNull(it)) }

private data class DeviceSignedItem(val identifier: DataElementIdentifier, val value: AnyDataElement)

private data class SessionTranscript(
    val deviceEngagementBytes: ByteArray?,
    val eReaderKeyBytes: ByteArray?,
    val handover: Handover,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SessionTranscript

        if (!deviceEngagementBytes.contentEquals(other.deviceEngagementBytes)) return false
        if (!eReaderKeyBytes.contentEquals(other.eReaderKeyBytes)) return false
        if (handover != other.handover) return false

        return true
    }

    override fun hashCode(): Int {
        var result = deviceEngagementBytes.contentHashCode()
        result = 31 * result + eReaderKeyBytes.contentHashCode()
        result = 31 * result + handover.hashCode()
        return result
    }
}

private fun SessionTranscript.toDataElement(): ListElement =
    listOf(
        deviceEngagementBytes?.let { EncodedCBORElement(it) } ?: NullElement(),
        eReaderKeyBytes?.let { EncodedCBORElement(it) } ?: NullElement(),
        handover.toDataElement(),
    ).toDataElement()

private data class Handover(
    val identifier: String,
    val handoverInfoHash: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Handover

        if (identifier != other.identifier) return false
        if (!handoverInfoHash.contentEquals(other.handoverInfoHash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = identifier.hashCode()
        result = 31 * result + handoverInfoHash.contentHashCode()
        return result
    }
}

private fun Handover.toDataElement(): ListElement = listOf(identifier.toDataElement(), handoverInfoHash.toDataElement()).toDataElement()

private fun HandoverInfo.toHandover(
    sha256: (ByteArray) -> ByteArray = { MessageDigest.getInstance("SHA-256").digest(it) },
): Handover {
    val (identifier, handoverInfoBytes) = when (this) {
        is HandoverInfo.OpenID4VPHandoverInfo -> {
            val element = listOf(
                clientId.clientId.toDataElement(),
                nonce.value.toDataElement(),
                ephemeralEncryptionKey?.computeThumbprint()?.decode()?.toDataElement() ?: NullElement(),
                responseUri.toExternalForm().toDataElement(),
            ).toDataElement()
            OpenId4VPSpec.OPENID4VP_HANDOVER_IDENTIFIER to cbor.encodeToByteArray(element)
        }

        is HandoverInfo.OpenID4VPDCAPIHandoverInfo -> {
            val element = listOf(
                origin.toExternalForm().toDataElement(),
                nonce.value.toDataElement(),
                ephemeralEncryptionKey?.computeThumbprint()?.decode()?.toDataElement() ?: NullElement(),
            )
            OpenId4VPSpec.OPENID4VP_DCAPI_HANDOVER_IDENTIFIER to cbor.encodeToByteArray(element)
        }
    }

    val handoverInfoHash = sha256(handoverInfoBytes)
    return Handover(identifier, handoverInfoHash)
}
