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
package eu.europa.ec.eudi.verifier.endpoint.domain

import arrow.core.nonEmptyListOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Test class focusing on JSON serialization for QesApproval.
 */
class QesApprovalSerializationTest {
    private val json =
        Json {
            prettyPrint = true
        }

    @Test
    fun `test QesApproval serialization and deserialization`() {
        // Create a DocumentDigest instance
        val documentDigest =
            DocumentDigest(
                label = Label("Example Contract"),
                hash = "7Qzm5EjuzXKSHFlc0OH9PP9qUaH-VBl2aGNbwYj1oOA",
                hashType = HashType.Default,
                signedProperties =
                    nonEmptyListOf(
                        Attribute(
                            attributeName = "test",
                        ),
                    ),
                circumstantialData = "test",
                href = URI.create("https://test"),
            )

        // Create a QesApproval instance
        val qesApproval =
            QesApproval(
                type = Type(QesApproval.TYPE),
                credentialIds = nonEmptyListOf(CredentialID("607510a9-c957-4095-906d-f99fd006c4ae")),
                hashAlgorithm = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
                signatureQualifier = SignatureQualifier.EuEidasQes,
                credentialId = null,
                documentDigests = nonEmptyListOf(documentDigest),
                numSignatures = 1u,
            )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesApproval)

        // Parse the JSON string to a JsonElement for inspection
        val jsonElement = json.parseToJsonElement(jsonString)
        assertTrue(jsonElement is JsonObject)

        // Verify JSON structure and values
        val jsonObject = jsonElement.jsonObject
        assertEquals(QesApproval.TYPE, jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.toString()?.trim('"'))

        // Deserialize back to QesApproval
        val deserializedQesApproval = json.decodeFromString<QesApproval>(jsonString)

        // Verify the deserialized object matches the original
        assertEquals(qesApproval.type, deserializedQesApproval.type)
        assertEquals(qesApproval.credentialIds, deserializedQesApproval.credentialIds)
        assertEquals(qesApproval.hashAlgorithm, deserializedQesApproval.hashAlgorithm)
        assertEquals(qesApproval.signatureQualifier?.value, deserializedQesApproval.signatureQualifier?.value)
        assertEquals(qesApproval.credentialId, deserializedQesApproval.credentialId)
        assertEquals(qesApproval.numSignatures, deserializedQesApproval.numSignatures)

        // Verify document digests
        assertEquals(qesApproval.documentDigests.size, deserializedQesApproval.documentDigests.size)
        val originalDigest = qesApproval.documentDigests[0]
        val deserializedDigest = deserializedQesApproval.documentDigests[0]
        assertEquals(originalDigest.label?.value, deserializedDigest.label?.value)
        assertEquals(originalDigest.hash, deserializedDigest.hash)
        assertEquals(originalDigest.hashType?.value, deserializedDigest.hashType?.value)
    }

    @Test
    fun `test QesApproval JSON structure`() {
        // Create a DocumentDigest instance
        val documentDigest =
            DocumentDigest(
                label = Label("Example Contract"),
                hash = "7Qzm5EjuzXKSHFlc0OH9PP9qUaH-VBl2aGNbwYj1oOA",
                hashType = HashType.Default,
                signedProperties =
                    nonEmptyListOf(
                        Attribute(
                            attributeName = "test",
                        ),
                    ),
                circumstantialData = "test",
                href = URI.create("https://test"),
                checksum =
                    Hash(
                        value = "test",
                        algorithmOID = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
                    ),
                access =
                    AccessControlMethod(
                        accessMode = AccessMode.Public,
                    ),
            )

        // Create a QesApproval instance
        val qesApproval =
            QesApproval(
                type = Type(QesApproval.TYPE),
                credentialIds = nonEmptyListOf(CredentialID("607510a9-c957-4095-906d-f99fd006c4ae")),
                hashAlgorithm = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
                signatureQualifier = SignatureQualifier.EuEidasQes,
                credentialId = null,
                documentDigests = nonEmptyListOf(documentDigest),
                numSignatures = 1u,
            )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesApproval)

        // Parse the JSON string to a JsonElement for inspection
        val jsonObject = json.parseToJsonElement(jsonString).jsonObject

        // Verify all expected fields are present with correct values
        assertEquals(QesApproval.TYPE, jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.toString()?.trim('"'))

        // Check credential_ids
        val credentialIds = jsonObject[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS]
        assertNotNull(credentialIds)
        assertTrue(credentialIds.toString().contains("607510a9-c957-4095-906d-f99fd006c4ae"))

        // Check transaction_data_hashes_alg
        val hashAlgorithms = jsonObject["hashAlgorithmOID"]
        assertNotNull(hashAlgorithms)
        assertTrue(hashAlgorithms.toString().contains("2.16.840.1.101.3.4.2.1"))

        // Check signatureQualifier
        val signatureQualifier = jsonObject[RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER]
        assertNotNull(signatureQualifier)
        assertEquals("\"eu_eidas_qes\"", signatureQualifier.toString())

        // Check documentDigests
        val documentDigests = jsonObject[RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_DOCUMENT_DIGESTS]
        assertNotNull(documentDigests)

        // Verify the first document digest
        val digestJson = documentDigests.toString()
        assertTrue(digestJson.contains("Example Contract"))
        assertTrue(digestJson.contains("7Qzm5EjuzXKSHFlc0OH9PP9qUaH-VBl2aGNbwYj1oOA"))
    }

    @Test
    fun `test QesApproval deserialization from sample JSON`() {
        val sample =
            """
            {
              "type": "https://cloudsignatureconsortium.org/2025/qes-approval",
              "credential_ids": [
                "xyz123"
              ],
              "credentialID": "GX0112348",
              "signatureQualifier": "eu_eidas_qes",
              "numSignatures": 2,
              "documentDigests": [
                {
                  "label": "Example Contract",
                  "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                  "hashType": "sodr",
                  "access": {
                    "type": "OTP",
                    "oneTimePassword": "51623"
                  },
                  "href": "https://protected.example/doc-01.pdf?token=...",
                  "checksum": {
                    "value": " HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                    "algorithmOID": "2.16.840.1.101.3.4.2.1"
                  }
                },
                {
                  "label": "Terms of Service",
                  "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                  "hashType": "sodr",
                  "access": {
                    "type": "public"
                  },
                  "href": "https://public.example/tos.pdf",
                  "checksum": {
                    "value": " HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                    "algorithmOID": "2.16.840.1.101.3.4.2.1"
                  }
                }
              ],
              "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
            }
            """.trimIndent()

        val qesApproval = json.decodeFromString<QesApproval>(sample)

        // Verify the deserialized object
        assertEquals(QesApproval.TYPE, qesApproval.type.value)
        assertEquals(1, qesApproval.credentialIds.size)
        assertEquals("xyz123", qesApproval.credentialIds[0].value)
        assertEquals("GX0112348", qesApproval.credentialId?.value)
        assertEquals("eu_eidas_qes", qesApproval.signatureQualifier?.value)
        assertEquals(2u, qesApproval.numSignatures)
        assertEquals("2.16.840.1.101.3.4.2.1", qesApproval.hashAlgorithm.value)
        assertEquals(2, qesApproval.documentDigests.size)

        val firstDigest = qesApproval.documentDigests[0]
        assertEquals("Example Contract", firstDigest.label?.value)
        assertEquals("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=", firstDigest.hash)
        assertEquals("sodr", firstDigest.hashType?.value)

        val secondDigest = qesApproval.documentDigests[1]
        assertEquals("Terms of Service", secondDigest.label?.value)
        assertEquals("HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=", secondDigest.hash)
        assertEquals("sodr", secondDigest.hashType?.value)
    }
}
