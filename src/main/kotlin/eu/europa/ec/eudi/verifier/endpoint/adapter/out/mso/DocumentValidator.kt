/*
 * Copyright (c) 2023-2026 European Commission
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

import arrow.core.*
import arrow.core.raise.*
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.msoMdocIssuance
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist.StatusListTokenValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import id.walt.cose.CoseKey
import id.walt.cose.CoseVerifier
import id.walt.cose.toCoseVerifier
import id.walt.crypto.keys.jwk.JWKKey
import id.walt.mdoc.crypto.MdocCryptoHelper
import id.walt.mdoc.objects.DeviceSigned
import id.walt.mdoc.objects.SessionTranscript
import id.walt.mdoc.objects.document.Document
import id.walt.mdoc.objects.elements.DeviceNameSpaces
import id.walt.mdoc.objects.mso.MobileSecurityObject
import id.walt.mdoc.objects.mso.ValidityInfo
import id.walt.mdoc.verification.MdocVerificationContext
import id.walt.mdoc.verification.MdocVerifier
import org.slf4j.LoggerFactory
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import kotlin.time.Instant

enum class ValidityInfoShouldBe {
    NotExpired,
    Ignored,
}

enum class IssuerSignedItemsShouldBe {
    Verified,
    Ignored,
}

sealed interface DocumentError {
    data object NoMatchingX5CShouldBe : DocumentError
    data class X5CNotTrusted(val cause: String?) : DocumentError
    data object CannotBeDecoded : DocumentError
    data class ExpiredValidityInfo(val validFrom: Instant, val validTo: Instant) : DocumentError
    data object DocumentTypeNotMatching : DocumentError
    data object InvalidIssuerSignedItems : DocumentError
    data object UnsupportedKeyType : DocumentError
    data object InvalidIssuerSignature : DocumentError
    data object DocumentHasBeenRevoked : DocumentError
    data object MissingDeviceSigned : DocumentError
    data class DeviceKeyNotAuthorizedToSignItems(val unauthorized: Map<NameSpace, NonEmptyList<DataElementIdentifier>>) : DocumentError
    data object InvalidDeviceSignature : DocumentError
}

private val log = LoggerFactory.getLogger(DocumentValidator::class.java)

class DocumentValidator(
    private val clock: Clock = Clock.System,
    private val validityInfoShouldBe: ValidityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
    private val issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
    private val statusListTokenValidator: StatusListTokenValidator?,
    private val isChainTrustedForAttestation: IsChainTrustedForAttestation<NonEmptyList<X509Certificate>, TrustAnchor>,
) {
    suspend fun ensureValid(
        document: Document,
        transactionId: TransactionId? = null,
        handoverInfo: HandoverInfo? = null,
    ): EitherNel<DocumentError, Document> =
        either {
            val issuerChain = ensureTrustedChain(document, isChainTrustedForAttestation)
            val mso = ensureMsoCanBeDecoded(document)

            zipOrAccumulate(
                { ensureNotExpiredValidityInfo(mso, clock, validityInfoShouldBe) },
                { ensureMatchingDocumentType(document, mso) },
                { ensureDigestsOfIssuerSignedItems(document, mso, issuerSignedItemsShouldBe) },
                {
                    ensureValidIssuerSignature(document, issuerChain)
                        .also { log.info("IssuerSigned validation succeeded") }
                },
                { ensureNotRevoked(mso, statusListTokenValidator, transactionId) },
            ) { _, _, _, _, _ -> document }
            if (null != handoverInfo) {
                ensureValidDeviceSigned(document, mso, handoverInfo)
                    .also { log.info("DeviceSigned validation succeeded") }
            }

            document
        }
}

private suspend fun Raise<Nel<DocumentError>>.ensureTrustedChain(
    document: Document,
    isChainTrustedForAttestation: IsChainTrustedForAttestation<NonEmptyList<X509Certificate>, TrustAnchor>,
): NonEmptyList<X509Certificate> =
    either {
        val issuerChain = ensureContainsChain(document)
        ensureTrustedChain(document.docType, issuerChain, isChainTrustedForAttestation)
    }.toEitherNel().bind()

private fun Raise<DocumentError>.ensureContainsChain(document: Document): Nel<X509Certificate> {
    val issuerAuth =
        ensureNotNull(document.issuerSigned.issuerAuth) {
            DocumentError.X5CNotTrusted("Missing issuerAuth")
        }

    val chain =
        run {
            val x5c = ensureNotNull(issuerAuth.unprotected.x5chain) { DocumentError.X5CNotTrusted("Missing x5chain") }
            val x5cBytes = x5c.map { it.rawBytes }.reduceOrNull(ByteArray::plus)

            catch({
                x5cBytes?.inputStream()
                    ?.use { inputStream ->
                        val factory: CertificateFactory = CertificateFactory.getInstance("X.509")
                        factory.generateCertificates(inputStream)
                    }
                    ?.map { certificate -> certificate as X509Certificate }
                    ?.toNonEmptyListOrNull()
            }) { raise(DocumentError.CannotBeDecoded) }
        }

    return ensureNotNull(chain) { DocumentError.X5CNotTrusted("Empty x5chain") }
}

private suspend fun Raise<DocumentError.X5CNotTrusted>.ensureTrustedChain(
    docType: String,
    issuerChain: NonEmptyList<X509Certificate>,
    isChainTrustedForAttestation: IsChainTrustedForAttestation<NonEmptyList<X509Certificate>, TrustAnchor>,
): Nel<X509Certificate> =
    when (isChainTrustedForAttestation.msoMdocIssuance(issuerChain, docType)) {
        is CertificationChainValidation.Trusted -> issuerChain
        is CertificationChainValidation.NotTrusted -> raise(DocumentError.X5CNotTrusted("Issuer X5C not trusted"))
        null -> throw IllegalStateException("Could not find Attestation Classification for docType '$docType'")
    }

private fun Raise<Nel<DocumentError.CannotBeDecoded>>.ensureMsoCanBeDecoded(document: Document): MobileSecurityObject =
    catch({ document.issuerSigned.decodeMobileSecurityObject() }) { raise(DocumentError.CannotBeDecoded.nel()) }

private fun Raise<DocumentError>.ensureNotExpiredValidityInfo(
    mso: MobileSecurityObject,
    clock: Clock,
    validityInfoShouldBe: ValidityInfoShouldBe,
) {
    fun ValidityInfo.notExpired() {
        val now = clock.now()
        ensure(now in validFrom..validUntil) {
            DocumentError.ExpiredValidityInfo(validFrom, validUntil)
        }
    }

    when (validityInfoShouldBe) {
        ValidityInfoShouldBe.NotExpired -> mso.validityInfo.notExpired()
        ValidityInfoShouldBe.Ignored -> Unit
    }
}

private fun Raise<DocumentError.DocumentTypeNotMatching>.ensureMatchingDocumentType(document: Document, mso: MobileSecurityObject) =
    ensure(document.docType == mso.docType) {
        DocumentError.DocumentTypeNotMatching
    }

private fun Raise<DocumentError.InvalidIssuerSignedItems>.ensureDigestsOfIssuerSignedItems(
    document: Document,
    mso: MobileSecurityObject,
    issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe,
) {
    if (issuerSignedItemsShouldBe == IssuerSignedItemsShouldBe.Verified) {
        catch({
            MdocVerifier.verifyIssuerSignedDataIntegrity(document, mso)
        }) {
            log.error("Failed to verify issuer signed data integrity for document", it)
            raise(DocumentError.InvalidIssuerSignedItems)
        }
    }
}

private suspend fun Raise<DocumentError>.ensureValidIssuerSignature(
    document: Document,
    chain: NonEmptyList<X509Certificate>,
) {
    val coseVerifier = coseVerifier(chain)
    ensure(document.issuerSigned.issuerAuth.verify(coseVerifier)) {
        DocumentError.InvalidIssuerSignature
    }
}

private suspend fun Raise<DocumentError>.coseVerifier(chain: NonEmptyList<X509Certificate>): CoseVerifier =
    catch({
        val jwk = JWKKey.importFromDerCertificate(chain.first().encoded).getOrThrow()
        jwk.toCoseVerifier()
    }) { raise(DocumentError.UnsupportedKeyType) }

private suspend fun Raise<DocumentError.DocumentHasBeenRevoked>.ensureNotRevoked(
    mso: MobileSecurityObject,
    statusListTokenValidator: StatusListTokenValidator?,
    transactionId: TransactionId?,
) {
    if (null != statusListTokenValidator) {
        catch({
            statusListTokenValidator.validate(mso, transactionId)
        }) {
            raise(DocumentError.DocumentHasBeenRevoked)
        }
    }
}

private suspend fun Raise<Nel<DocumentError>>.ensureValidDeviceSigned(
    document: Document,
    mso: MobileSecurityObject,
    handoverInfo: HandoverInfo,
): Document {
    val deviceSigned = ensureNotNull(document.deviceSigned) { DocumentError.MissingDeviceSigned.nel() }
    val deviceNameSpaces = deviceSigned.namespaces

    return zipOrAccumulate(
        { ensureValidKeyAuthorizations(mso, deviceNameSpaces.value) },
        { ensureValidDeviceAuthentication(mso, deviceSigned, handoverInfo) },
    ) { _, _ -> document }
}

private fun Raise<DocumentError.DeviceKeyNotAuthorizedToSignItems>.ensureValidKeyAuthorizations(
    mso: MobileSecurityObject,
    nameSpaces: DeviceNameSpaces,
) {
    if (nameSpaces.entries.isNotEmpty()) {
        val keyAuthorizations = mso.deviceKeyInfo.keyAuthorizations
        ensureNotNull(keyAuthorizations) {
            DocumentError.DeviceKeyNotAuthorizedToSignItems(
                nameSpaces.entries
                    .filterValues { it.entries.isNotEmpty() }
                    .mapValues { (_, dataElements) -> checkNotNull(dataElements.entries.map { it.key }.toNonEmptyListOrNull()) },
            )
        }
        val fullyAuthorizedNameSpaces = keyAuthorizations.namespaces.orEmpty()
        val authorizedDataElementsPerNameSpace = keyAuthorizations.dataElements.orEmpty()

        val unauthorized = buildMap {
            nameSpaces.entries.forEach { (nameSpace, dataElements) ->
                dataElements
                    .entries
                    .filter {
                            (identifier, _) ->
                        nameSpace !in fullyAuthorizedNameSpaces && identifier !in authorizedDataElementsPerNameSpace[nameSpace].orEmpty()
                    }
                    .map { it.key }
                    .toNonEmptyListOrNull()
                    ?.let { put(nameSpace, it) }
            }
        }
        ensure(unauthorized.isEmpty()) {
            DocumentError.DeviceKeyNotAuthorizedToSignItems(unauthorized)
        }
    }
}

private suspend fun Raise<DocumentError>.ensureValidDeviceAuthentication(
    mso: MobileSecurityObject,
    deviceSigned: DeviceSigned,
    handoverInfo: HandoverInfo,
) {
    val deviceKey = mso.deviceKeyInfo.deviceKey
    val coseVerifier = coseVerifier(deviceKey)
    val deviceSignature = ensureNotNull(deviceSigned.deviceAuth.deviceSignature) {
        DocumentError.MissingDeviceSigned
    }
    val deviceAuthenticationBytes = MdocCryptoHelper.buildDeviceAuthenticationBytes(
        handoverInfo.toSessionTranscript(),
        mso.docType,
        deviceSigned.namespaces,
    )
    ensure(deviceSignature.verifyDetached(coseVerifier, deviceAuthenticationBytes)) {
        DocumentError.InvalidDeviceSignature
    }
}

private suspend fun Raise<DocumentError>.coseVerifier(coseKey: CoseKey): CoseVerifier =
    catch({
        val jwk = JWKKey.importJWK(jsonSupport.encodeToString(coseKey.toJWK())).getOrThrow()
        jwk.toCoseVerifier()
    }) { raise(DocumentError.UnsupportedKeyType) }

private fun HandoverInfo.toSessionTranscript(): SessionTranscript {
    val context = when (this) {
        is HandoverInfo.OpenID4VPDCAPIHandoverInfo ->
            MdocVerificationContext(
                expectedAudience = origin.toExternalForm(),
                expectedNonce = nonce.value,
                jwkThumbprint = ephemeralEncryptionKey?.computeThumbprint()?.toString(),
                responseUri = null,
                isDcApi = true,
            )

        is HandoverInfo.OpenID4VPHandoverInfo ->
            MdocVerificationContext(
                expectedAudience = clientId.clientId,
                expectedNonce = nonce.value,
                jwkThumbprint = ephemeralEncryptionKey?.computeThumbprint()?.toString(),
                responseUri = responseUri.toString(),
                isDcApi = false,
            )
    }

    return MdocVerifier.buildSessionTranscriptForContext(context)
}
