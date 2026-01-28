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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Test class focusing on JSON serialization for QesAuthorization.
 */
class QesAuthorizationSerializationTest {

    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
    }

    @Test
    fun `test QesAuthorization serialization and deserialization`() {
        // Create a DocumentDigest instance
        val documentDigest = DocumentDigest(
            label = Label("Example Contract"),
            hash = "7Qzm5EjuzXKSHFlc0OH9PP9qUaH-VBl2aGNbwYj1oOA",
            hashAlgorithm = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
            documentLocation = null,
            documentAccessMethod = null,
            dataToBeSignedRepresentation = null,
            dataToBeSignedRepresentationHashAlgorithm = null,
        )

        // Create a QesAuthorization instance
        val qesAuthorization = QesAuthorization(
            type = QesAuthorization.TYPE,
            credentialIds = nonEmptyListOf("607510a9-c957-4095-906d-f99fd006c4ae"),
            hashAlgorithms = nonEmptyListOf("SHA-256"),
            signatureQualifier = SignatureQualifier.EuEidasQes,
            credentialId = null,
            documentDigests = nonEmptyListOf(documentDigest),
            processId = null,
        )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesAuthorization)

        // Parse the JSON string to a JsonElement for inspection
        val jsonElement = json.parseToJsonElement(jsonString)
        assertTrue(jsonElement is JsonObject)

        // Verify JSON structure and values
        val jsonObject = jsonElement.jsonObject
        assertEquals(QesAuthorization.TYPE, jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.toString()?.trim('"'))

        // Deserialize back to QesAuthorization
        val deserializedQesAuthorization = json.decodeFromString<QesAuthorization>(jsonString)

        // Verify the deserialized object matches the original
        assertEquals(qesAuthorization.type, deserializedQesAuthorization.type)
        assertEquals(qesAuthorization.credentialIds, deserializedQesAuthorization.credentialIds)
        assertEquals(qesAuthorization.hashAlgorithms, deserializedQesAuthorization.hashAlgorithms)
        assertEquals(qesAuthorization.signatureQualifier?.value, deserializedQesAuthorization.signatureQualifier?.value)
        assertEquals(qesAuthorization.credentialId, deserializedQesAuthorization.credentialId)
        assertEquals(qesAuthorization.processId, deserializedQesAuthorization.processId)

        // Verify document digests
        assertEquals(qesAuthorization.documentDigests.size, deserializedQesAuthorization.documentDigests.size)
        val originalDigest = qesAuthorization.documentDigests[0]
        val deserializedDigest = deserializedQesAuthorization.documentDigests[0]
        assertEquals(originalDigest.label.value, deserializedDigest.label.value)
        assertEquals(originalDigest.hash, deserializedDigest.hash)
        assertEquals(originalDigest.hashAlgorithm?.value, deserializedDigest.hashAlgorithm?.value)
    }

    @Test
    fun `test QesAuthorization JSON structure`() {
        // Create a DocumentDigest instance
        val documentDigest = DocumentDigest(
            label = Label("Example Contract"),
            hash = "7Qzm5EjuzXKSHFlc0OH9PP9qUaH-VBl2aGNbwYj1oOA",
            hashAlgorithm = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
            documentLocation = null,
            documentAccessMethod = null,
            dataToBeSignedRepresentation = null,
            dataToBeSignedRepresentationHashAlgorithm = null,
        )

        // Create a QesAuthorization instance
        val qesAuthorization = QesAuthorization(
            type = QesAuthorization.TYPE,
            credentialIds = nonEmptyListOf("607510a9-c957-4095-906d-f99fd006c4ae"),
            hashAlgorithms = nonEmptyListOf("SHA-256"),
            signatureQualifier = SignatureQualifier.EuEidasQes,
            credentialId = null,
            documentDigests = nonEmptyListOf(documentDigest),
            processId = null,
        )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesAuthorization)

        // Parse the JSON string to a JsonElement for inspection
        val jsonObject = json.parseToJsonElement(jsonString).jsonObject

        // Verify all expected fields are present with correct values
        assertEquals(QesAuthorization.TYPE, jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.toString()?.trim('"'))

        // Check credential_ids
        val credentialIds = jsonObject[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS]
        assertNotNull(credentialIds)
        assertTrue(credentialIds.toString().contains("607510a9-c957-4095-906d-f99fd006c4ae"))

        // Check transaction_data_hashes_alg
        val hashAlgorithms = jsonObject[OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS]
        assertNotNull(hashAlgorithms)
        assertTrue(hashAlgorithms.toString().contains("SHA-256"))

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
        assertTrue(digestJson.contains("2.16.840.1.101.3.4.2.1"))
    }

    @Test
    fun `test QesAuthorization deserialization from sample JSON`() {
        val sample = """
            {
                "type": "qes_authorization",
                "credential_ids":["607510a9-c957-4095-906d-f99fd006c4ae"],
                "signatureQualifier": "eu_eidas_qes",
                "documentDigests": [
                    {
                    "label": "Example Contract",
                    "hash": "7Qzm5EjuzXKSHFlc0OH9PP9qUaH-VBl2aGNbwYj1oOA",
                    "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
                    }
                ]
            }
        """.trimIndent()

        val qesAuthorization = json.decodeFromString<QesAuthorization>(sample)

        // Verify the deserialized object
        assertEquals(QesAuthorization.TYPE, qesAuthorization.type)
        assertEquals(1, qesAuthorization.credentialIds.size)
        assertEquals("607510a9-c957-4095-906d-f99fd006c4ae", qesAuthorization.credentialIds[0])
        assertEquals("eu_eidas_qes", qesAuthorization.signatureQualifier?.value)
        assertEquals(1, qesAuthorization.documentDigests.size)

        val digest = qesAuthorization.documentDigests[0]
        assertEquals("Example Contract", digest.label.value)
        assertEquals("7Qzm5EjuzXKSHFlc0OH9PP9qUaH-VBl2aGNbwYj1oOA", digest.hash)
        assertEquals("2.16.840.1.101.3.4.2.1", digest.hashAlgorithm?.value)
    }
}
