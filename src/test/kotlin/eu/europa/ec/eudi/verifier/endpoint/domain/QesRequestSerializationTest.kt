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
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Test class focusing on JSON serialization for QesRequest.
 */
class QesRequestSerializationTest {
    private val json =
        Json {
            prettyPrint = true
        }

    @Test
    fun `test QesRequest serialization and deserialization`() {
        // Create a SignatureRequest instance backed by a document reference
        val signatureRequest =
            SignatureRequest.SignatureRequestWithDocumentReference(
                signatureQualifier = SignatureQualifier.EuEidasQes,
                responseURI = URI.create("https://rp.example/qes/receive"),
                signatureFormat = SignatureFormat(SignatureFormat.PADES),
                conformanceLevel = ConformanceLevel("AdES-B-B"),
                signedEnvelopeProperty = SignedEnvelopeProperty(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_CERTIFICATION),
                label = Label("Service Agreement #2025-09"),
                access =
                    AccessControlMethod(
                        accessMode = AccessMode.Public,
                    ),
                href = URI.create("https://protected.rp.example/contracts/2025-09-01.pdf?token=..."),
                checksum =
                    Hash(
                        value = "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                        algorithmOID = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
                    ),
                signAlgo = "1.2.840.113549.1.1.1",
            )

        // Create a QesRequest instance
        val qesRequest =
            QesRequest(
                type = Type(QesRequest.TYPE),
                credentialIds = nonEmptyListOf(CredentialID("qes-cert-1")),
                signatureRequests = nonEmptyListOf(signatureRequest),
            )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesRequest)

        // Parse the JSON string to a JsonElement for inspection
        val jsonElement = json.parseToJsonElement(jsonString)
        assertTrue(jsonElement is JsonObject)

        // Verify JSON structure and values
        val jsonObject = jsonElement.jsonObject
        assertEquals(
            QesRequest.TYPE,
            jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.jsonPrimitive?.content,
        )

        // Deserialize back to QesRequest
        val deserializedQesRequest = json.decodeFromString<QesRequest>(jsonString)

        // Verify the deserialized object matches the original
        assertEquals(qesRequest.type.value, deserializedQesRequest.type.value)
        assertEquals(1, deserializedQesRequest.signatureRequests.size)

        val originalRequest = qesRequest.signatureRequests.first()
        val deserializedRequest = deserializedQesRequest.signatureRequests.first()
        assertEquals(originalRequest.signatureQualifier.value, deserializedRequest.signatureQualifier.value)
        assertEquals(originalRequest.responseURI, deserializedRequest.responseURI)
        assertEquals(originalRequest.signatureFormat?.value, deserializedRequest.signatureFormat?.value)
        assertEquals(originalRequest.conformanceLevel?.value, deserializedRequest.conformanceLevel?.value)
        assertEquals(originalRequest.signedEnvelopeProperty?.value, deserializedRequest.signedEnvelopeProperty?.value)

        // Verify document reference details
        val originalReference = assertIs<SignatureRequest.SignatureRequestWithDocumentReference>(originalRequest)
        val deserializedReference = assertIs<SignatureRequest.SignatureRequestWithDocumentReference>(deserializedRequest)
        assertEquals(originalReference.label?.value, deserializedReference.label?.value)
        assertEquals(originalReference.href, deserializedReference.href)
        assertEquals(originalReference.checksum?.value, deserializedReference.checksum?.value)
        assertEquals(originalReference.checksum?.algorithmOID?.value, deserializedReference.checksum?.algorithmOID?.value)
        assertEquals(originalReference.access?.accessMode?.value, deserializedReference.access?.accessMode?.value)
    }

    @Test
    fun `test QesRequest serialization and deserialization with document data`() {
        // Create a SignatureRequest instance backed by document data
        val signatureRequest =
            SignatureRequest.SignatureRequestWithDocumentData(
                signatureQualifier = SignatureQualifier.EuEidasQes,
                responseURI = URI.create("https://rp.example/qes/receive"),
                signatureFormat = SignatureFormat(SignatureFormat.JADES),
                conformanceLevel = ConformanceLevel("AdES-B-B"),
                signedEnvelopeProperty = SignedEnvelopeProperty(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ATTACHED),
                label = Label("Annex A - JSON config"),
                document = "eyJleGFtcGxlS2V5IjoiZXhhbXBsZVZhbHVlIn0K",
                documentType = DocumentType(RQES.DOCUMENTS_DOCUMENT_TYPE_SFD),
                signAlgo = "1.2.840.113549.1.1.1",
            )

        // Create a QesRequest instance
        val qesRequest =
            QesRequest(
                type = Type(QesRequest.TYPE),
                credentialIds = nonEmptyListOf(CredentialID("qes-cert-1")),
                signatureRequests = nonEmptyListOf(signatureRequest),
            )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesRequest)

        // Parse the JSON string to a JsonElement for inspection
        val jsonElement = json.parseToJsonElement(jsonString)
        assertTrue(jsonElement is JsonObject)

        // Verify JSON structure and values
        val jsonObject = jsonElement.jsonObject
        assertEquals(
            QesRequest.TYPE,
            jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.jsonPrimitive?.content,
        )

        // Deserialize back to QesRequest
        val deserializedQesRequest = json.decodeFromString<QesRequest>(jsonString)

        // Verify the deserialized object matches the original
        assertEquals(qesRequest.type.value, deserializedQesRequest.type.value)
        assertEquals(1, deserializedQesRequest.signatureRequests.size)

        val originalRequest = qesRequest.signatureRequests.first()
        val deserializedRequest = deserializedQesRequest.signatureRequests.first()
        assertEquals(originalRequest.signatureQualifier.value, deserializedRequest.signatureQualifier.value)
        assertEquals(originalRequest.responseURI, deserializedRequest.responseURI)
        assertEquals(originalRequest.signatureFormat?.value, deserializedRequest.signatureFormat?.value)
        assertEquals(originalRequest.conformanceLevel?.value, deserializedRequest.conformanceLevel?.value)
        assertEquals(originalRequest.signedEnvelopeProperty?.value, deserializedRequest.signedEnvelopeProperty?.value)

        // Verify document data details
        val originalData = assertIs<SignatureRequest.SignatureRequestWithDocumentData>(originalRequest)
        val deserializedData = assertIs<SignatureRequest.SignatureRequestWithDocumentData>(deserializedRequest)
        assertEquals(originalData.label?.value, deserializedData.label?.value)
        assertEquals(originalData.document, deserializedData.document)
        assertEquals(originalData.documentType.value, deserializedData.documentType.value)
    }

    @Test
    fun `test QesRequest JSON structure`() {
        // Create a SignatureRequest instance backed by a document reference
        val signatureRequest =
            SignatureRequest.SignatureRequestWithDocumentReference(
                signatureQualifier = SignatureQualifier.EuEidasQes,
                responseURI = URI.create("https://rp.example/qes/receive"),
                signatureFormat = SignatureFormat(SignatureFormat.PADES),
                conformanceLevel = ConformanceLevel("AdES-B-B"),
                signedEnvelopeProperty = SignedEnvelopeProperty(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_CERTIFICATION),
                label = Label("Service Agreement #2025-09"),
                access =
                    AccessControlMethod(
                        accessMode = AccessMode.OneTimePassword,
                        oneTimePassword = OneTimePassword("51623"),
                    ),
                href = URI.create("https://protected.rp.example/contracts/2025-09-01.pdf?token=..."),
                checksum =
                    Hash(
                        value = "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                        algorithmOID = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
                    ),
                signAlgo = "1.2.840.113549.1.1.1",
            )

        // Create a QesRequest instance
        val qesRequest =
            QesRequest(
                type = Type(QesRequest.TYPE),
                credentialIds = nonEmptyListOf(CredentialID("qes-cert-1")),
                signatureRequests = nonEmptyListOf(signatureRequest),
            )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesRequest)

        // Parse the JSON string to a JsonElement for inspection
        val jsonObject = json.parseToJsonElement(jsonString).jsonObject

        // Check envelope type
        val type = jsonObject[OpenId4VPSpec.TRANSACTION_DATA_TYPE]
        assertNotNull(type)
        assertEquals(QesRequest.TYPE, type.jsonPrimitive.content)

        // The per-document fields live inside the nested signatureRequests entries.
        val signatureRequestsJson = jsonObject["signatureRequests"]?.jsonArray
        assertNotNull(signatureRequestsJson)
        assertEquals(1, signatureRequestsJson.size)
        val signatureRequestJson = signatureRequestsJson[0].jsonObject

        // Check signatureQualifier
        val signatureQualifier = signatureRequestJson[RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER]
        assertNotNull(signatureQualifier)
        assertEquals("eu_eidas_qes", signatureQualifier.jsonPrimitive.content)

        // Check responseURI
        val responseURI = signatureRequestJson[RQES.SIGNATURE_REQUEST_RESPONSE_URI]
        assertNotNull(responseURI)
        assertTrue(responseURI.toString().contains("https://rp.example/qes/receive"))

        // Check signature_format
        val signatureFormat = signatureRequestJson[RQES.ADES_PARAMETERS_SIGNATURE_FORMAT]
        assertNotNull(signatureFormat)
        assertEquals(SignatureFormat.PADES, signatureFormat.jsonPrimitive.content)

        // Check conformance_level
        val conformanceLevel = signatureRequestJson[RQES.ADES_PARAMETERS_SIGNATURE_CONFORMANCE_LEVEL]
        assertNotNull(conformanceLevel)
        assertEquals("AdES-B-B", conformanceLevel.jsonPrimitive.content)

        // Check signed_envelope_property
        val signedEnvelopeProperty = signatureRequestJson[RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY]
        assertNotNull(signedEnvelopeProperty)
        assertEquals("Certification", signedEnvelopeProperty.jsonPrimitive.content)

        // Check document reference fields
        val digestJson = signatureRequestJson.toString()
        assertTrue(digestJson.contains("Service Agreement #2025-09"))
        assertTrue(digestJson.contains("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="))
    }

    @Test
    fun `test QesRequest deserialization from sample JSON`() {
        val sample =
            """
            {
              "type": "https://cloudsignatureconsortium.org/2025/qes",
              "credential_ids": [
                "qes-cert-1"
              ],
              "signatureRequests": [
                {
                  "label": "Service Agreement #2025-09",
                  "checksum": {
                    "value": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                    "algorithmOID": "2.16.840.1.101.3.4.2.1"
                  },
                  "access": {
                    "type": "OTP",
                    "oneTimePassword": "51623"
                  },
                  "href": "https://protected.rp.example/contracts/2025-09-01.pdf?token=...",
                  "signature_format": "P",
                  "conformance_level": "AdES-B-B",
                  "signed_envelope_property": "Certification",
                  "signatureQualifier": "eu_eidas_qes",
                  "signAlgo": "1.2.840.113549.1.1.1"
                },
                {
                  "label": "Annex A - JSON config",
                  "href": "data:application/json;base64,eyJleGFtcGxlS2V5IjoiZXhhbXBsZVZhbHVlIn0K",
                  "signature_format": "J",
                  "conformance_level": "AdES-B-B",
                  "signed_envelope_property": "Attached",
                  "signAlgo": "1.2.840.113549.1.1.1",
                  "checksum": {
                    "value": "cuKv8Ee9H/rQsteQ1MQZ2Ld2ERXRkkulihFh3/XOXFQ=",
                    "algorithmOID": "2.16.840.1.101.3.4.2.1"
                  },
                  "signatureQualifier": "eu_eidas_qes",
                  "responseURI": "https://rp.example/qes/receive"
                }
              ]
            } 
            """.trimIndent()
        val parsed = json.decodeFromString<QesRequest>(sample)

        // Verify the envelope
        assertEquals(QesRequest.TYPE, parsed.type.value)
        assertEquals(1, parsed.credentialIds.size)
        assertEquals("qes-cert-1", parsed.credentialIds[0].value)

        // The per-document fields now live inside the nested SignatureRequest entries.
        val qesRequests = parsed.signatureRequests
        assertEquals(2, qesRequests.size)

        // Verify the first signature request
        val first = assertIs<SignatureRequest.SignatureRequestWithDocumentReference>(qesRequests[0])
        assertEquals("eu_eidas_qes", first.signatureQualifier.value)
        assertEquals(SignatureFormat.PADES, first.signatureFormat?.value)
        assertEquals("AdES-B-B", first.conformanceLevel?.value)
        assertEquals("Certification", first.signedEnvelopeProperty?.value)
        assertNull(first.responseURI)
        assertEquals("Service Agreement #2025-09", first.label?.value)
        assertEquals(
            URI.create("https://protected.rp.example/contracts/2025-09-01.pdf?token=..."),
            first.href,
        )
        assertEquals("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=", first.checksum?.value)
        assertEquals("2.16.840.1.101.3.4.2.1", first.checksum?.algorithmOID?.value)
        assertEquals(RQES.ACCESS_MODE_OTP, first.access?.accessMode?.value)
        assertEquals("51623", first.access?.oneTimePassword?.value)

        // Verify the second signature request
        val second = assertIs<SignatureRequest.SignatureRequestWithDocumentReference>(qesRequests[1])
        assertEquals("eu_eidas_qes", second.signatureQualifier.value)
        assertEquals(SignatureFormat.JADES, second.signatureFormat?.value)
        assertEquals("AdES-B-B", second.conformanceLevel?.value)
        assertEquals("Attached", second.signedEnvelopeProperty?.value)
        assertEquals(URI.create("https://rp.example/qes/receive"), second.responseURI)
        assertEquals("Annex A - JSON config", second.label?.value)
        assertEquals(
            URI.create("data:application/json;base64,eyJleGFtcGxlS2V5IjoiZXhhbXBsZVZhbHVlIn0K"),
            second.href,
        )
        assertEquals("cuKv8Ee9H/rQsteQ1MQZ2Ld2ERXRkkulihFh3/XOXFQ=", second.checksum?.value)
        assertEquals("2.16.840.1.101.3.4.2.1", second.checksum?.algorithmOID?.value)
        assertNull(second.access)
    }
}
