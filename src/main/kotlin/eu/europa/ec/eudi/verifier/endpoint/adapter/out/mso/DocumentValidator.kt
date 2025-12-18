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
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mdocauth.DeviceAuthentication
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.MSO
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toStdlibInstant
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
    data class DeviceKeyNotAuthorizedToSignItems(
        val unauthorized: Map<NameSpace, NonEmptyList<DataElementIdentifier>>,
        val authorizations: KeyAuthorizations?,
    ) : DocumentError
    class DevicePublicKeyCannotBeParsed(val cause: Throwable) : DocumentError
    class DeviceKeyIsNotEC(val cause: Throwable) : DocumentError
    data object InvalidDeviceSignature : DocumentError
}

class DocumentValidator(
    private val clock: Clock = Clock.System,
    private val validityInfoShouldBe: ValidityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
    private val issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
    private val provideTrustSource: ProvideTrustSource,
    private val statusListTokenValidator: StatusListTokenValidator?,
) {

    suspend fun ensureValid(document: MDoc): EitherNel<DocumentError, MDoc> = ensureValid(document, null, null)
    suspend fun ensureValid(
        document: MDoc,
        sessionTranscript: SessionTranscript,
    ): EitherNel<DocumentError, MDoc> = ensureValid(document, null, sessionTranscript)
    suspend fun ensureValid(
        document: MDoc,
        transactionId: TransactionId?,
        sessionTranscript: SessionTranscript?,
    ): EitherNel<DocumentError, MDoc> =
        either {
            document.decodeMso()

            val x5CShouldBe = ensureMatchingX5CShouldBe(document, provideTrustSource)

            val issuerChain = ensureTrustedChain(document, x5CShouldBe)
            zipOrAccumulate(
                { ensureNotExpiredValidityInfo(document, clock, validityInfoShouldBe) },
                { ensureMatchingDocumentType(document) },
                { ensureDigestsOfIssuerSignedItems(document, issuerSignedItemsShouldBe) },
                { ensureValidIssuerSignature(document, issuerChain, x5CShouldBe.caCertificates()) },
                { ensureNotRevoked(document, statusListTokenValidator, transactionId) },
            ) { _, _, _, _, _ -> document }
            if (null != sessionTranscript) {
                ensureValidDeviceSigned(document, sessionTranscript)
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

private fun Raise<Nel<DocumentError>>.ensureValidDeviceSigned(document: MDoc, sessionTranscript: SessionTranscript): MDoc {
    val mso = checkNotNull(document.MSO)

    val deviceSigned = ensureNotNull(document.deviceSigned) { DocumentError.MissingDeviceSigned.nel() }
    val nameSpaces = DeviceNameSpaces.fromEncodedCborElement(deviceSigned.nameSpaces)

    return zipOrAccumulate(
        { ensureValidKeyAuthorizations(mso, nameSpaces) },
        { ensureValidDeviceAuthentication(document, sessionTranscript) },
    ) { _, _ -> document }
}

private fun Raise<DocumentError.DeviceKeyNotAuthorizedToSignItems>.ensureValidKeyAuthorizations(mso: MSO, nameSpaces: DeviceNameSpaces) {
    if (nameSpaces.isNotEmpty()) {
        val keyAuthorizations = mso.deviceKeyInfo.keyAuthorizations?.let { KeyAuthorizations.fromMapElement(it) }
        ensureNotNull(keyAuthorizations) {
            DocumentError.DeviceKeyNotAuthorizedToSignItems(
                unauthorized = nameSpaces.mapValues { (_, dataElements) -> dataElements.items.map { it.identifier } },
                authorizations = null,
            )
        }
        val fullyAuthorizedNameSpaces = keyAuthorizations.nameSpaces.orEmpty()
        val authorizedDataElementsPerNameSpace = keyAuthorizations.dataElements.orEmpty()

        val unauthorized = buildMap {
            nameSpaces.forEach { (nameSpace, dataElements) ->
                dataElements
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
            DocumentError.DeviceKeyNotAuthorizedToSignItems(unauthorized = unauthorized, authorizations = keyAuthorizations)
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

private fun Raise<DocumentError>.ensureValidDeviceAuthentication(document: MDoc, sessionTranscript: SessionTranscript) {
    val mso = checkNotNull(document.MSO)
    val deviceKeyCryptoProviderKeyInfo = mso.deviceKeyInfo.cryptoProviderKeyInfo().bind()

    val deviceSigned = checkNotNull(document.deviceSigned)
    val deviceAuthentication = DeviceAuthentication(sessionTranscript.toListElement(), mso.docType.value, deviceSigned.nameSpaces)

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
