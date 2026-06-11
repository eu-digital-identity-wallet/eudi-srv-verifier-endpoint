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

import arrow.core.NonEmptyList
import arrow.core.getOrElse
import arrow.core.nonEmptyListOf
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.Ignored
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.usingTrustAnchors
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.keystore.loadKeyStore
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.toConsultationAttestationClassifications
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.toInstant
import org.junit.jupiter.api.Nested
import org.slf4j.LoggerFactory
import java.net.URL
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import kotlin.test.*
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationClassifications as ConsultationAttestationClassifications

private object Data {

    /**
     * Contains three documents,
     *
     * The first and the second are valid
     * The 3d has expired validity info
     */
    val ThreeDocumentVP = Data::class.java.getResource(
        "/deviceresponsevalidator/ThreeDocumentDeviceResponse.txt",
    )!!.readText()

    /**
     * An mDL
     */
    val MdlVP = Data::class.java.getResource(
        "/deviceresponsevalidator/mDL-deviceresponse.txt",
    )!!.readText()

    /**
     * An mDL with Key Authorizations and Device Signed Items
     */
    val MdlAuthorizedDeviceSigned = Data::class.java.getResource(
        "/deviceresponsevalidator/mDL-authorizeddevicesigned.txt",
    )!!.readText()

    /**
     * An mDL with Unauthorized Device Signed Items
     */
    val MdlUnauthorizedDeviceSigned = Data::class.java.getResource(
        "/deviceresponsevalidator/mDL-unauthorizeddevicesigned.txt",
    )!!.readText()

    /**
     * Various MSO MDoc Credentials issued by Kotlin and Python issuers
     * to ensure they are being properly validated
     */
    val attestationsToValidate =
        nonEmptyListOf(
            "/deviceresponsevalidator/kotlin-issuer/pid.txt" to "eu.europa.ec.eudi.pid.1",
            "/deviceresponsevalidator/kotlin-issuer/mdl.txt" to "org.iso.18013.5.1.mDL",
            "/deviceresponsevalidator/python-issuer/pid.txt" to "eu.europa.ec.eudi.pid.1",
            "/deviceresponsevalidator/python-issuer/mdl.txt" to "org.iso.18013.5.1.mDL",
            "/deviceresponsevalidator/python-issuer/cor.txt" to "eu.europa.ec.eudi.cor.1",
            "/deviceresponsevalidator/python-issuer/ehic.txt" to "eu.europa.ec.eudi.ehic.1",
            "/deviceresponsevalidator/python-issuer/employeeID.txt" to "eu.europa.ec.eudi.employee.1",
            "/deviceresponsevalidator/python-issuer/healthID.txt" to "eu.europa.ec.eudi.hiid.1",
            "/deviceresponsevalidator/python-issuer/iban.txt" to "eu.europa.ec.eudi.iban.1",
            "/deviceresponsevalidator/python-issuer/loyaltyCard.txt" to "eu.europa.ec.eudi.loyalty.1",
            "/deviceresponsevalidator/python-issuer/msisdn.txt" to "eu.europa.ec.eudi.msisdn.1",
            "/deviceresponsevalidator/python-issuer/pda1.txt" to "eu.europa.ec.eudi.pda1.1",
            "/deviceresponsevalidator/python-issuer/photoID.txt" to "org.iso.23220.2.photoid.1",
            "/deviceresponsevalidator/python-issuer/por.txt" to "eu.europa.ec.eudi.por.1",
            "/deviceresponsevalidator/python-issuer/seaFarer.txt" to "eu.europa.ec.eudi.seafarer.1",
            "/deviceresponsevalidator/python-issuer/tax.txt" to "eu.europa.ec.eudi.tax.1",
            "/deviceresponsevalidator/python-issuer/reservation.txt" to "org.iso.18013.5.1.reservation",
        )

    val trustedIssuers: NonEmptyList<X509Certificate> by lazy {
        val keyStore = loadKeyStore(location = "classpath:trusted-issuers.jks", password = "")
        val certs = run {
            val aliases = keyStore.aliases().toList()
            aliases.filter { keyStore.isCertificateEntry(it) }.map { keyStore.getCertificate(it) as X509Certificate }
        }.toNonEmptyListOrNull()
        checkNotNull(certs) { "Unable to load X509 Certificates from 'classpath:trusted-issuers.jks'" }
    }

    val attestationClassifications = jsonSupport.decodeFromString<AttestationClassifications>(
        Data::class.java.getResource("/deviceresponsevalidator/attestationclassifications.json")!!.readText(),
    ).toConsultationAttestationClassifications()
}

private val log = LoggerFactory.getLogger(DeviceResponseValidatorTest::class.java)

class DeviceResponseValidatorTest {

    private val clock = run {
        val testDate = LocalDateTime(2024, 11, 1, 0, 0)
        Clock.fixed(
            testDate.toInstant(kotlinx.datetime.TimeZone.of("Europe/Athens")),
            kotlinx.datetime.TimeZone.of("Europe/Athens"),
        )
    }

    @Test
    fun `a vp_token where the 3d document has an invalid validity info should fail`() = runTest {
        val invalidDocument = run {
            val isChainTrusted = IsChainTrustedForContextF.usingTrustAnchors(Data.trustedIssuers) {
                isRevocationEnabled = false
                date = clock.now().toJavaDate()
            }
            val validator = deviceResponseValidator(isChainTrusted, ValidityInfoShouldBe.NotExpired, Data.attestationClassifications, clock)
            val validated = validator.ensureValid(Data.ThreeDocumentVP)
            val invalidDocuments =
                assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull())
                    .invalidDocuments
            assertEquals(1, invalidDocuments.size)
            invalidDocuments.head
        }

        assertEquals(2, invalidDocument.index)
        val documentError = run {
            assertEquals(1, invalidDocument.errors.size)
            invalidDocument.errors.head
        }
        assertIs<DocumentError.ExpiredValidityInfo>(documentError)
    }

    @Test
    fun `a vp_token where the 3d document has an invalid validity info should not fail when skip`() = runTest {
        val validDocuments = run {
            val isChainTrusted = IsChainTrustedForContextF.usingTrustAnchors(Data.trustedIssuers) {
                isRevocationEnabled = false
                date = clock.now().toJavaDate()
            }
            val validator = deviceResponseValidator(isChainTrusted, ValidityInfoShouldBe.Ignored, Data.attestationClassifications, clock)
            val validated = validator.ensureValid(Data.ThreeDocumentVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(3, validDocuments.size)
    }

    @Test
    fun `a vp_token having a single document with invalid chain should fail`() = runTest {
        val invalidDocument = run {
            val isChainTrusted = IsChainTrustedForContextF.usingTrustAnchors(Data.trustedIssuers) {
                isRevocationEnabled = false
                date = clock.now().toJavaDate()
            }
            val validator = deviceResponseValidator(isChainTrusted, ValidityInfoShouldBe.NotExpired, Data.attestationClassifications, clock)
            val validated = validator.ensureValid(Data.MdlVP)
            val invalidDocuments = assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull()).invalidDocuments
            assertEquals(1, invalidDocuments.size)
            invalidDocuments.head
        }
        assertEquals(0, invalidDocument.index)
        val documentError = run {
            assertEquals(1, invalidDocument.errors.size)
            invalidDocument.errors.head
        }
        assertIs<DocumentError.X5CNotTrusted>(documentError)
    }

    @Test
    fun `a vp_token having a single document skipping chain validation should be valid`() = runTest {
        val validDocuments = run {
            val validator =
                deviceResponseValidator(
                    IsChainTrustedForContextF.Ignored,
                    ValidityInfoShouldBe.NotExpired,
                    Data.attestationClassifications,
                    clock,
                )
            val validated = validator.ensureValid(Data.MdlVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(1, validDocuments.size)
    }

    @Test
    fun `ensure all mso mdoc attestations issued by kotlin and python issuer can be validated`() = runTest {
        val validator =
            deviceResponseValidator(
                IsChainTrustedForContextF.Ignored,
                ValidityInfoShouldBe.Ignored,
                Data.attestationClassifications,
                Clock.System,
            )
        Data.attestationsToValidate.forEach { (resource, docType) ->
            log.info("Checking $resource")
            val vpToken = Data::class.java.getResource(resource)!!.readText()
            val validated = validator.ensureValid(vpToken)
            val documents = validated.getOrElse { error -> fail("Failed to validated $resource, error: $error") }
            assertEquals(1, documents.size)
            val document = documents.first()
            assertEquals(docType, document.docType)
        }
    }

    @Nested
    inner class KeyAuthorizationTest {

        private val handoverInfo: HandoverInfo by lazy {
            val verifierId = VerifierId.PreRegistered(
                originalClientId = "client_id",
                accessCertificate = TestContext.verifierId.accessCertificate,
            )

            HandoverInfo.OpenID4VPHandoverInfo(
                clientId = verifierId,
                nonce = Nonce("nonce"),
                ephemeralEncryptionKey = null,
                responseUri = URL("https://example.com/direct_post"),
            )
        }

        @Test
        fun `device signed items in an authorized namespace are accepted`() = runTest {
            val validDocuments = run {
                val vpValidator =
                    deviceResponseValidator(
                        IsChainTrustedForContextF.Ignored,
                        ValidityInfoShouldBe.Ignored,
                        Data.attestationClassifications,
                        clock,
                    )

                val validated = vpValidator.ensureValid(Data.MdlAuthorizedDeviceSigned, handoverInfo = handoverInfo)
                validated.getOrElse { error -> error("Validation failed: $error") }
            }

            assertEquals(1, validDocuments.size)
        }

        @Test
        fun `device signed items in an unauthorized namespace should fail`() = runTest {
            val invalidDocument = run {
                val vpValidator =
                    deviceResponseValidator(
                        IsChainTrustedForContextF.Ignored,
                        ValidityInfoShouldBe.Ignored,
                        Data.attestationClassifications,
                        clock,
                    )

                val validated = vpValidator.ensureValid(Data.MdlUnauthorizedDeviceSigned, handoverInfo = handoverInfo)
                val invalidDocuments =
                    assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull()).invalidDocuments
                assertEquals(1, invalidDocuments.size)
                invalidDocuments.head
            }

            assertEquals(0, invalidDocument.index)
            val documentError = run {
                assertEquals(1, invalidDocument.errors.size)
                invalidDocument.errors.head
            }
            assertIs<DocumentError.DeviceKeyNotAuthorizedToSignItems>(documentError)
        }
    }
}

private fun deviceResponseValidator(
    isChainTrusted: IsChainTrustedForContextF<NonEmptyList<X509Certificate>, VerificationContext, TrustAnchor>,
    validityInfo: ValidityInfoShouldBe,
    attestationClassifications: ConsultationAttestationClassifications,
    clock: Clock,
): DeviceResponseValidator {
    val documentValidator = DocumentValidator(
        clock,
        validityInfo,
        IssuerSignedItemsShouldBe.Verified,
        isChainTrustedForAttestation = IsChainTrustedForAttestation(isChainTrusted, attestationClassifications),
        statusListTokenValidator = null,
    )
    return DeviceResponseValidator(documentValidator)
}
