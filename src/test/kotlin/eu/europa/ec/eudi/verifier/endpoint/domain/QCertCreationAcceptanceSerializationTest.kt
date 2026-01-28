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
import java.net.URL
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Test class focusing on JSON serialization for QCertCreationAcceptance.
 */
class QCertCreationAcceptanceSerializationTest {

    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
    }

    @Test
    fun `test QCertCreationAcceptance serialization and deserialization`() {
        // Create a QCertCreationAcceptance instance
        val qCertCreationAcceptance = QCertCreationAcceptance(
            type = QCertCreationAcceptance.TYPE,
            credentialIds = nonEmptyListOf("credential1", "credential2"),
            hashAlgorithms = nonEmptyListOf("SHA-256", "SHA-512"),
            termsAndConditions = URL("https://example.com/terms"),
            documentHash = "dGVzdEhhc2g", // "testHash" in Base64 without padding
            hashAlgorithm = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
        )

        // Serialize to JSON
        val jsonString = json.encodeToString(qCertCreationAcceptance)

        // Parse the JSON string to a JsonElement for inspection
        val jsonElement = json.parseToJsonElement(jsonString)
        assertTrue(jsonElement is JsonObject)

        // Verify JSON structure and values
        val jsonObject = jsonElement.jsonObject
        assertEquals(QCertCreationAcceptance.TYPE, jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.toString()?.trim('"'))

        // Deserialize back to QCertCreationAcceptance
        val deserializedQCertCreationAcceptance = json.decodeFromString<QCertCreationAcceptance>(jsonString)

        // Verify the deserialized object matches the original
        assertEquals(qCertCreationAcceptance.type, deserializedQCertCreationAcceptance.type)
        assertEquals(qCertCreationAcceptance.credentialIds, deserializedQCertCreationAcceptance.credentialIds)
        assertEquals(qCertCreationAcceptance.hashAlgorithms, deserializedQCertCreationAcceptance.hashAlgorithms)
        assertEquals(
            qCertCreationAcceptance.termsAndConditions.toString(),
            deserializedQCertCreationAcceptance.termsAndConditions.toString(),
        )
        assertEquals(qCertCreationAcceptance.documentHash, deserializedQCertCreationAcceptance.documentHash)
        assertEquals(qCertCreationAcceptance.hashAlgorithm.value, deserializedQCertCreationAcceptance.hashAlgorithm.value)
    }

    @Test
    fun `test QCertCreationAcceptance JSON structure`() {
        // Create a QCertCreationAcceptance instance
        val qCertCreationAcceptance = QCertCreationAcceptance(
            type = QCertCreationAcceptance.TYPE,
            credentialIds = nonEmptyListOf("credential1", "credential2"),
            hashAlgorithms = nonEmptyListOf("SHA-256", "SHA-512"),
            termsAndConditions = URL("https://example.com/terms"),
            documentHash = "dGVzdEhhc2g", // "testHash" in Base64 without padding
            hashAlgorithm = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
        )

        // Serialize to JSON
        val jsonString = json.encodeToString(qCertCreationAcceptance)

        // Parse the JSON string to a JsonElement for inspection
        val jsonObject = json.parseToJsonElement(jsonString).jsonObject

        // Verify all expected fields are present with correct values
        assertEquals(QCertCreationAcceptance.TYPE, jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.toString()?.trim('"'))

        // Check credential_ids
        val credentialIds = jsonObject[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS]
        assertNotNull(credentialIds)
        assertTrue(credentialIds.toString().contains("credential1"))
        assertTrue(credentialIds.toString().contains("credential2"))

        // Check transaction_data_hashes_alg
        val hashAlgorithms = jsonObject[OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS]
        assertNotNull(hashAlgorithms)
        assertTrue(hashAlgorithms.toString().contains("SHA-256"))
        assertTrue(hashAlgorithms.toString().contains("SHA-512"))

        // Check QC_terms_conditions_uri
        val termsAndConditions = jsonObject[RQES.QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_TERM_AND_CONDITIONS_URI]
        assertNotNull(termsAndConditions)
        assertEquals("\"https://example.com/terms\"", termsAndConditions.toString())

        // Check QC_hash
        val documentHash = jsonObject[RQES.QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_HASH]
        assertNotNull(documentHash)
        assertEquals("\"dGVzdEhhc2g\"", documentHash.toString())

        // Check QC_hashAlgorithmOID
        val hashAlgorithm = jsonObject[RQES.QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_HASH_ALGORITHM]
        assertNotNull(hashAlgorithm)
        assertEquals("\"2.16.840.1.101.3.4.2.1\"", hashAlgorithm.toString())
    }

    @Test
    fun `test QCertCreationAcceptance deserialization from JSON string`() {
        // JSON string representing a QCertCreationAcceptance object
        val jsonString = """
        {
            "type": "qcert_creation_acceptance",
            "credential_ids": ["credential3", "credential4"],
            "transaction_data_hashes_alg": ["SHA-384", "SHA-512"],
            "QC_terms_conditions_uri": "https://example.org/terms-and-conditions",
            "QC_hash": "ZXhhbXBsZUhhc2g",
            "QC_hashAlgorithmOID": "2.16.840.1.101.3.4.2.2"
        }
        """.trimIndent()

        // Deserialize the JSON string to a QCertCreationAcceptance object
        val deserializedQCertCreationAcceptance = json.decodeFromString<QCertCreationAcceptance>(jsonString)

        // Verify the deserialized object has the expected values
        assertEquals(QCertCreationAcceptance.TYPE, deserializedQCertCreationAcceptance.type)
        assertEquals(nonEmptyListOf("credential3", "credential4"), deserializedQCertCreationAcceptance.credentialIds)
        assertEquals(nonEmptyListOf("SHA-384", "SHA-512"), deserializedQCertCreationAcceptance.hashAlgorithms)
        assertEquals("https://example.org/terms-and-conditions", deserializedQCertCreationAcceptance.termsAndConditions.toString())
        assertEquals("ZXhhbXBsZUhhc2g", deserializedQCertCreationAcceptance.documentHash)
        assertEquals("2.16.840.1.101.3.4.2.2", deserializedQCertCreationAcceptance.hashAlgorithm.value)
    }
}
