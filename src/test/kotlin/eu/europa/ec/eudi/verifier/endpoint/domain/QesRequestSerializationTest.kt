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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
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
            ignoreUnknownKeys = true
        }

    @Test
    fun `test QesRequest serialization and deserialization`() {
        // Create a DocumentReference instance
        val documentReference =
            DocumentReference(
                documentDigests = Label("Example Contract"),
                href = URI.create("https://protected.example/doc-01.pdf?token=..."),
                checksum =
                    Hash(
                        value = "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                        algorithmOID = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
                    ),
                access =
                    AccessControlMethod(
                        accessMode = AccessMode.Public,
                    ),
            )

        // Create a QesRequest instance
        val qesRequest =
            QesRequest(
                signatureQualifier = SignatureQualifier.EuEidasQes,
                responseURI = URI.create("https://rp.example/qes/receive"),
                signatureFormat = SignatureFormat(SignatureFormat.PADES),
                conformanceLevel = ConformanceLevel("AdES-B-B"),
                signedEnvelopeProperty = SignedEnvelopeProperty(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_CERTIFICATION),
                documentReference = documentReference,
            )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesRequest)

        // Parse the JSON string to a JsonElement for inspection
        val jsonElement = json.parseToJsonElement(jsonString)
        assertTrue(jsonElement is JsonObject)

        // Verify JSON structure and values
        val jsonObject = jsonElement.jsonObject
        assertEquals(
            "eu_eidas_qes",
            jsonObject[RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER]?.toString()?.trim('"'),
        )

        // Deserialize back to QesRequest
        val deserializedQesRequest = json.decodeFromString<QesRequest>(jsonString)

        // Verify the deserialized object matches the original
        assertEquals(qesRequest.signatureQualifier.value, deserializedQesRequest.signatureQualifier.value)
        assertEquals(qesRequest.responseURI, deserializedQesRequest.responseURI)
        assertEquals(qesRequest.signatureFormat?.value, deserializedQesRequest.signatureFormat?.value)
        assertEquals(qesRequest.conformanceLevel?.value, deserializedQesRequest.conformanceLevel?.value)
        assertEquals(qesRequest.signedEnvelopeProperty?.value, deserializedQesRequest.signedEnvelopeProperty?.value)

        // Verify document reference
        val originalReference = assertNotNull(qesRequest.documentReference)
        val deserializedReference = assertNotNull(deserializedQesRequest.documentReference)
        assertEquals(originalReference.documentDigests?.value, deserializedReference.documentDigests?.value)
        assertEquals(originalReference.href, deserializedReference.href)
        assertEquals(originalReference.checksum?.value, deserializedReference.checksum?.value)
        assertEquals(originalReference.checksum?.algorithmOID?.value, deserializedReference.checksum?.algorithmOID?.value)
        assertEquals(originalReference.access?.accessMode?.value, deserializedReference.access?.accessMode?.value)
    }

    @Test
    fun `test QesRequest JSON structure`() {
        // Create a DocumentReference instance
        val documentReference =
            DocumentReference(
                documentDigests = Label("Example Contract"),
                href = URI.create("https://protected.example/doc-01.pdf?token=..."),
                checksum =
                    Hash(
                        value = "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                        algorithmOID = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"), // SHA-256 OID
                    ),
                access =
                    AccessControlMethod(
                        accessMode = AccessMode.OneTimePassword,
                        oneTimePassword = OneTimePassword("51623"),
                    ),
            )

        // Create a QesRequest instance
        val qesRequest =
            QesRequest(
                signatureQualifier = SignatureQualifier.EuEidasQes,
                responseURI = URI.create("https://rp.example/qes/receive"),
                signatureFormat = SignatureFormat(SignatureFormat.PADES),
                conformanceLevel = ConformanceLevel("AdES-B-B"),
                signedEnvelopeProperty = SignedEnvelopeProperty(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_CERTIFICATION),
                documentReference = documentReference,
            )

        // Serialize to JSON
        val jsonString = json.encodeToString(qesRequest)

        // Parse the JSON string to a JsonElement for inspection
        val jsonObject = json.parseToJsonElement(jsonString).jsonObject

        // Check signatureQualifier
        val signatureQualifier = jsonObject[RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER]
        assertNotNull(signatureQualifier)
        assertEquals("\"eu_eidas_qes\"", signatureQualifier.toString())

        // Check responseURI
        val responseURI = jsonObject[RQES.SIGNATURE_REQUEST_RESPONSE_URI]
        assertNotNull(responseURI)
        assertTrue(responseURI.toString().contains("https://rp.example/qes/receive"))

        // Check signature_format
        val signatureFormat = jsonObject[RQES.ADES_PARAMETERS_SIGNATURE_FORMAT]
        assertNotNull(signatureFormat)
        assertEquals("\"${SignatureFormat.PADES}\"", signatureFormat.toString())

        // Check conformance_level
        val conformanceLevel = jsonObject[RQES.ADES_PARAMETERS_SIGNATURE_CONFORMANCE_LEVEL]
        assertNotNull(conformanceLevel)
        assertEquals("\"AdES-B-B\"", conformanceLevel.toString())

        // Check signed_envelope_property
        val signedEnvelopeProperty = jsonObject[RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY]
        assertNotNull(signedEnvelopeProperty)
        assertEquals("\"Certification\"", signedEnvelopeProperty.toString())

        // Check documentReference
        val documentReferenceJson = jsonObject[RQES.DOCUMENTS_DOCUMENT_REFERENCE]
        assertNotNull(documentReferenceJson)
        val digestJson = documentReferenceJson.toString()
        assertTrue(digestJson.contains("Example Contract"))
        assertTrue(digestJson.contains("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="))
    }

    @Test
    fun `test QesRequest deserialization from sample JSON`() {

        val sample = """
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

        // Parse the normative JSON
        val root = json.parseToJsonElement(sample).jsonObject

        // Verify the envelope
        assertEquals(
            "https://cloudsignatureconsortium.org/2025/qes",
            root[OpenId4VPSpec.TRANSACTION_DATA_TYPE]?.jsonPrimitive?.content,
        )
        val credentialIds = root[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS]?.jsonArray
        assertNotNull(credentialIds)
        assertEquals(1, credentialIds.size)
        assertEquals("qes-cert-1", credentialIds[0].jsonPrimitive.content)

        val signatureRequests = root["signatureRequests"]?.jsonArray
        assertNotNull(signatureRequests)
        assertEquals(2, signatureRequests.size)

        // Map each signature request entry into a QesRequest using its document reference fields
        val qesRequests =
            signatureRequests.map { element ->
                val obj = element.jsonObject
                val checksum =
                    obj[RQES.DOCUMENTS_DOCUMENT_REFERENCE_CHECKSUM]?.jsonObject?.let { checksumObj ->
                        Hash(
                            value = checksumObj[RQES.DOCUMENTS_DOCUMENT_REFERENCE_HASH_VALUE]!!.jsonPrimitive.content,
                            algorithmOID =
                                HashAlgorithmOID(
                                    checksumObj[RQES.DOCUMENTS_DOCUMENT_REFERENCE_HASH_ALGORITHM_OID]!!.jsonPrimitive.content,
                                ),
                        )
                    }
                val access =
                    obj[RQES.DOCUMENTS_DOCUMENT_REFERENCE_ACCESS]?.jsonObject?.let { accessObj ->
                        AccessControlMethod(
                            accessMode = AccessMode(accessObj[RQES.ACCESS_CONTROL_METHOD_TYPE]!!.jsonPrimitive.content),
                            oneTimePassword =
                                accessObj[RQES.DOCUMENT_ACCESS_METHOD_OTP]?.jsonPrimitive?.content?.let { OneTimePassword(it) },
                        )
                    }
                QesRequest(
                    signatureQualifier =
                        SignatureQualifier(
                            obj[RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER]!!.jsonPrimitive.content,
                        ),
                    responseURI = obj[RQES.SIGNATURE_REQUEST_RESPONSE_URI]?.jsonPrimitive?.content?.let { URI.create(it) },
                    signatureFormat = SignatureFormat(obj[RQES.ADES_PARAMETERS_SIGNATURE_FORMAT]!!.jsonPrimitive.content),
                    conformanceLevel = ConformanceLevel(obj[RQES.ADES_PARAMETERS_SIGNATURE_CONFORMANCE_LEVEL]!!.jsonPrimitive.content),
                    signedEnvelopeProperty =
                        SignedEnvelopeProperty(obj[RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY]!!.jsonPrimitive.content),
                    documentReference =
                        DocumentReference(
                            documentDigests = Label(obj[RQES.DOCUMENTS_DOCUMENT_REFERENCE_LABEL]!!.jsonPrimitive.content),
                            href = URI.create(obj[RQES.DOCUMENTS_DOCUMENT_REFERENCE_HREF]!!.jsonPrimitive.content),
                            checksum = checksum,
                            access = access,
                        ),
                )
            }

        assertEquals(2, qesRequests.size)

        // Verify the first signature request
        val first = qesRequests[0]
        assertEquals("eu_eidas_qes", first.signatureQualifier.value)
        assertEquals(SignatureFormat.PADES, first.signatureFormat?.value)
        assertEquals("AdES-B-B", first.conformanceLevel?.value)
        assertEquals("Certification", first.signedEnvelopeProperty?.value)
        assertNull(first.responseURI)
        val firstReference = assertNotNull(first.documentReference)
        assertEquals("Service Agreement #2025-09", firstReference.documentDigests?.value)
        assertEquals(
            URI.create("https://protected.rp.example/contracts/2025-09-01.pdf?token=..."),
            firstReference.href,
        )
        assertEquals("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=", firstReference.checksum?.value)
        assertEquals("2.16.840.1.101.3.4.2.1", firstReference.checksum?.algorithmOID?.value)
        assertEquals(RQES.ACCESS_MODE_OTP, firstReference.access?.accessMode?.value)
        assertEquals("51623", firstReference.access?.oneTimePassword?.value)

        // Verify the second signature request
        val second = qesRequests[1]
        assertEquals("eu_eidas_qes", second.signatureQualifier.value)
        assertEquals(SignatureFormat.JADES, second.signatureFormat?.value)
        assertEquals("AdES-B-B", second.conformanceLevel?.value)
        assertEquals("Attached", second.signedEnvelopeProperty?.value)
        assertEquals(URI.create("https://rp.example/qes/receive"), second.responseURI)
        val secondReference = assertNotNull(second.documentReference)
        assertEquals("Annex A - JSON config", secondReference.documentDigests?.value)
        assertEquals(
            URI.create("data:application/json;base64,eyJleGFtcGxlS2V5IjoiZXhhbXBsZVZhbHVlIn0K"),
            secondReference.href,
        )
        assertEquals("cuKv8Ee9H/rQsteQ1MQZ2Ld2ERXRkkulihFh3/XOXFQ=", secondReference.checksum?.value)
        assertEquals("2.16.840.1.101.3.4.2.1", secondReference.checksum?.algorithmOID?.value)
        assertNull(secondReference.access)
    }
}
