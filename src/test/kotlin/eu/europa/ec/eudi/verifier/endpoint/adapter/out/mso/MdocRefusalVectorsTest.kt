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

import arrow.core.nonEmptyListOf
import arrow.core.raise.either
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationClassifications
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationIdentifierPredicate
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.TestUtils
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.usingTrustAnchors
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import eu.europa.ec.eudi.verifier.endpoint.domain.toJavaDate
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayInputStream
import java.net.URL
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Instant

/**
 * Negative test vectors for mdoc DeviceResponses presented over OpenID4VP 1.0 (redirect, `direct_post.jwt`).
 *
 * The vectors come from https://github.com/EgorKhaklin/polaris-id, `lab/interop/negative-vectors`
 * (`mdoc-vectors.json`, commit 458909f7, Apache-2.0), where `make_mdoc_vectors.py` mints them.
 * Each response in `mdoc-refusal-vectors.json` is a valid DeviceResponse with exactly one thing changed
 * (the control `md-accept-redirect` has nothing changed). The keys and certificates are TEST material
 * derived from public seeds.
 *
 * The vectors are bound to the values below: the Client Identifier, the `nonce`, the `response_uri` and the
 * Response Encryption Key of the request the Wallet answered, and to the instant they were minted at.
 */
class MdocRefusalVectorsTest {
    @Test
    fun `the control is accepted`() = accepted("md-accept-redirect")

    @Test
    fun `session transcript with a different nonce is refused`() = refusedWithInvalidDeviceSignature("md-st-nonce")

    @Test
    fun `session transcript with another verifier's client_id is refused`() = refusedWithInvalidDeviceSignature("md-st-client-id-other")

    @Test
    fun `session transcript with a client_id missing its prefix is refused`() =
        refusedWithInvalidDeviceSignature("md-st-client-id-no-prefix")

    @Test
    fun `session transcript with a different response_uri is refused`() = refusedWithInvalidDeviceSignature("md-st-response-uri")

    @Test
    fun `session transcript with the thumbprint of another encryption key is refused`() =
        refusedWithInvalidDeviceSignature("md-st-thumbprint-other-key")

    @Test
    fun `session transcript without a thumbprint is refused`() = refusedWithInvalidDeviceSignature("md-st-thumbprint-absent")

    @Test
    fun `session transcript with a DC API handover for a redirect request is refused`() =
        refusedWithInvalidDeviceSignature("md-st-dcapi-handover-on-redirect")

    @Test
    fun `device signature made with another key is refused`() = refusedWithInvalidDeviceSignature("md-devicesig-other-key")

    @Test
    fun `device signature over another docType is refused`() = refusedWithInvalidDeviceSignature("md-devicesig-doctype-other")

    @Test
    fun `device key of the wrong kty and crv is refused`() =
        refused("md-devicekey-kty-crv") { assertIs<DocumentError.DevicePublicKeyCannotBeParsed>(it) }

    @Test
    fun `device signed items in an unauthorized namespace are refused`() =
        refused("md-devicesigned-unauthorized-ns") {
            val error = assertIs<DocumentError.DeviceKeyNotAuthorizedToSignItems>(it)
            assertEquals(mapOf("org.example.device" to nonEmptyListOf("device_note")), error.unauthorized)
        }

    @Test
    fun `issuer signature with a flipped bit is refused`() =
        refused("md-issuerauth-sig-flipped") { assertIs<DocumentError.InvalidIssuerSignature>(it) }

    @Test
    fun `issuer signature in DER instead of raw form is refused`() =
        refused("md-issuerauth-sig-der") { assertIs<DocumentError.InvalidIssuerSignature>(it) }

    @Test
    fun `an issuer signed item with a modified value is refused`() =
        refused("md-digest-value-modified") { assertIs<DocumentError.InvalidIssuerSignedItems>(it) }

    @Test
    fun `an issuer signed item that was re-encoded is refused`() =
        refused("md-digest-reencoded-item") { assertIs<DocumentError.InvalidIssuerSignedItems>(it) }

    @Test
    fun `an issuer signed item whose digest id is absent from the MSO is refused`() =
        refused("md-digest-id-absent") { assertIs<DocumentError.InvalidIssuerSignedItems>(it) }

    @Test
    fun `a value digest of the wrong length is refused`() =
        refused("md-digest-length") { assertIs<DocumentError.InvalidIssuerSignedItems>(it) }

    @Test
    fun `a document docType that differs from the MSO docType is refused`() =
        refused("md-doctype-vs-mso") { assertIs<DocumentError.DocumentTypeNotMatching>(it) }

    private fun accepted(id: String) =
        runTest {
            val validated = either { validator.ensureValid(vector(id), handoverInfo = handoverInfo) }
            val documents = assertNotNull(validated.getOrNull(), "$id: expected to be accepted, got ${validated.leftOrNull()}")
            assertEquals(1, documents.size)
        }

    private fun refusedWithInvalidDeviceSignature(id: String) = refused(id) { assertIs<DocumentError.InvalidDeviceSignature>(it) }

    /**
     * Asserts that the vector is refused with exactly one document error, and hands that error to [asserter].
     */
    private fun refused(
        id: String,
        asserter: (DocumentError) -> Unit,
    ) = runTest {
        val validated = either { validator.ensureValid(vector(id), handoverInfo = handoverInfo) }
        val invalidDocuments =
            assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull(), "$id: expected to be refused")
                .invalidDocuments
        assertEquals(1, invalidDocuments.size, id)
        assertEquals(0, invalidDocuments.head.index, id)
        assertEquals(1, invalidDocuments.head.errors.size, "$id: ${invalidDocuments.head.errors}")
        asserter(invalidDocuments.head.errors.head)
    }

    private companion object {
        private val fixture = Json.parseToJsonElement(TestUtils.loadResource("mdoc-refusal-vectors.json")).jsonObject

        // The certificates are valid 2026-01-01 to 2030-01-01, the MSO 2026-09-30 to 2027-09-30.
        // The clock is fixed at the instant the vectors were minted for: 2026-10-01T00:00:00Z
        private val clock =
            Clock.fixed(Instant.fromEpochSeconds(1790812800L), kotlinx.datetime.TimeZone.UTC)

        private val trustAnchor: X509Certificate =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificate(
                    ByteArrayInputStream(
                        fixture
                            .getValue("trust_anchor_pem")
                            .jsonPrimitive.content
                            .toByteArray(),
                    ),
                ) as X509Certificate

        // The Client Identifier is used as is: the vectors do not depend on how a Verifier proves it
        private val handoverInfo =
            HandoverInfo.OpenID4VPHandoverInfo(
                clientId =
                    VerifierId.PreRegistered(
                        originalClientId = "x509_san_dns:verifier.example",
                        accessCertificate = TestContext.verifierId.accessCertificate,
                    ),
                nonce = Nonce("mG3v7Rz0qLw5Hc1TfYb8Nd"),
                ephemeralEncryptionKey =
                    JWK.parse(
                        """
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "q-r_7SMggaD1kSPhH-La1lPcvD7H7qlbr393gXS5ZRU",
                            "y": "6sb3MD839wVM-3zXjFLm-OsLg01Fn8uougTr6d57HOk",
                            "use": "enc",
                            "alg": "ECDH-ES",
                            "kid": "enc-1"
                        }
                        """.trimIndent(),
                    ),
                responseUri = URL("https://verifier.example/response"),
            )

        private val validator: DeviceResponseValidator by lazy {
            DeviceResponseValidator(
                DocumentValidator(
                    clock,
                    ValidityInfoShouldBe.NotExpired,
                    IssuerSignedItemsShouldBe.Verified,
                    isChainTrustedForAttestation =
                        IsChainTrustedForAttestation(
                            IsChainTrustedForContextF.usingTrustAnchors(nonEmptyListOf(trustAnchor)) {
                                isRevocationEnabled = false
                                date = clock.now().toJavaDate()
                            },
                            AttestationClassifications(
                                eaAs =
                                    mapOf(
                                        "mDL" to
                                            AttestationIdentifierPredicate.mdocMatching("^org\\.iso\\.18013\\.5\\.1\\.mDL$".toRegex()),
                                    ),
                            ),
                        ),
                    statusListTokenValidator = null,
                ),
            )
        }

        private fun vector(id: String): String =
            fixture
                .getValue("responses")
                .jsonObject
                .getValue(id)
                .jsonPrimitive.content
    }
}
