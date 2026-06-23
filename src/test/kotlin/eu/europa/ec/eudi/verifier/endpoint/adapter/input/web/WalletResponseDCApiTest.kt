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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import eu.europa.ec.eudi.verifier.endpoint.domain.RFC6749
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import eu.europa.ec.eudi.verifier.endpoint.port.input.ProfileTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.RequestTypeTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Tests the initialization of a Transaction over the Digital Credentials API (DC API),
 * for both the OpenId4VP and the HAIP profiles, and for both signed and unsigned requests.
 */
@VerifierApplicationTest([WalletResponseDCApiTest.Config::class])
@TestPropertySource(
    properties = [
        "verifier.clientIdPrefix=x509_hash",
        "verifier.originalClientId=i7jZiSqa4GXNh1LzBwD2lVtKIcIhpinRQRo8BHSVMx0",
        "verifier.clientMetadata.responseEncryption.algorithm=ECDH-ES",
    ],
)
internal class WalletResponseDCApiTest {
    @Autowired
    private lateinit var client: WebTestClient

    @Autowired
    private lateinit var config: VerifierConfig

    @TestConfiguration
    internal class Config {
        @Bean
        @Primary
        fun validateVerifiablePresentation(): ValidateVerifiablePresentation = ValidateVerifiablePresentation.NoOp
    }

    /**
     * Asserts the common Authorization Request claims/parameters of a DC API request, regardless of
     * whether they were conveyed unsigned (as plain parameters) or signed (as Request Object claims).
     */
    private fun assertDCApiRequest(
        request: JsonObject,
        expectedNonce: String,
    ) {
        assertEquals(
            OpenId4VPSpec.RESPONSE_MODE_DCAPI,
            request[RFC6749.RESPONSE_MODE]?.jsonPrimitive?.contentOrNull,
            "response_mode must be '${OpenId4VPSpec.RESPONSE_MODE_DCAPI}'",
        )
        assertEquals(
            OpenId4VPSpec.VP_TOKEN,
            request[RFC6749.RESPONSE_TYPE]?.jsonPrimitive?.contentOrNull,
            "response_type must be '${OpenId4VPSpec.VP_TOKEN}'",
        )
        assertEquals(
            expectedNonce,
            request[OpenId4VPSpec.NONCE]?.jsonPrimitive?.contentOrNull,
            "nonce must be echoed back",
        )

        assertNotNull(request[OpenId4VPSpec.DCQL_QUERY]?.jsonObject, "dcql_query is missing")

        val clientMetadata = assertNotNull(request[OpenId4VPSpec.CLIENT_METADATA]?.jsonObject, "client_metadata is missing")
        assertNotNull(
            clientMetadata[OpenId4VPSpec.VP_FORMATS_SUPPORTED]?.jsonObject,
            "vp_formats_supported is missing",
        )
    }

    @Test
    fun `openid4vp - unsigned dc_api request is initialized`(): Unit =
        runBlocking {
            val initTransaction =
                VerifierApiClient
                    .loadInitDCApiTransactionTO("09-dcApi-dcql.json")
                    .copy(profile = ProfileTO.OpenId4VP, requestType = RequestTypeTO.Unsigned)

            val (body, transactionId) = VerifierApiClient.initDCApiTransaction(client, initTransaction)
            assertNotNull(transactionId, "Transaction-Id header is missing")
            assertEquals(transactionId, body["transaction_id"]?.jsonPrimitive?.contentOrNull)

            // for an unsigned request, the 'request' is a plain JSON object holding the request parameters
            val request = assertNotNull(body["request"]?.jsonObject, "request is not a JSON object")
            assertDCApiRequest(request, initTransaction.nonce)

            // an unsigned request advertises the supported response encryption methods in client_metadata
            val supportedEncryptionMethods = assertNotNull(request.supportedEncryptionMethods())
            assertEquals(config.clientMetaData.responseEncryptionOption.encryptionMethods, supportedEncryptionMethods)
        }

    @Test
    fun `openid4vp - signed dc_api request is initialized`(): Unit =
        runBlocking {
            val initTransaction =
                VerifierApiClient
                    .loadInitDCApiTransactionTO("09-dcApi-dcql.json")
                    .copy(profile = ProfileTO.OpenId4VP, requestType = RequestTypeTO.Signed)

            val (body, transactionId) = VerifierApiClient.initDCApiTransaction(client, initTransaction)
            assertNotNull(transactionId, "Transaction-Id header is missing")
            assertEquals(transactionId, body["transaction_id"]?.jsonPrimitive?.contentOrNull)

            // for a signed request, the 'request' is a Request Object (JWT)
            val requestJwt = assertNotNull(body["request"]?.jsonPrimitive?.contentOrNull, "request is not a JWT string")
            val (_, claims) = TestUtils.parseJWTIntoClaims(requestJwt)
            assertDCApiRequest(claims, initTransaction.nonce)

            // a signed DC API request must contain the expected_origins claim
            val expectedOrigins = assertNotNull(claims[OpenId4VPSpec.DCAPI_EXPECTED_ORIGINS], "expected_origins is missing")
            assertTrue(expectedOrigins.toString().contains("https://verifier.example.com"))
        }

    @Test
    fun `haip - unsigned dc_api request is initialized`(): Unit =
        runBlocking {
            // HAIP mandates the x509_hash Client Identifier Prefix
            assertIs<VerifierId.X509Hash>(config.verifierId)

            val initTransaction =
                VerifierApiClient
                    .loadInitDCApiTransactionTO("09-dcApi-dcql.json")
                    .copy(profile = ProfileTO.HAIP, requestType = RequestTypeTO.Unsigned)

            val (body, transactionId) = VerifierApiClient.initDCApiTransaction(client, initTransaction)
            assertNotNull(transactionId, "Transaction-Id header is missing")

            val request = assertNotNull(body["request"]?.jsonObject, "request is not a JSON object")
            assertDCApiRequest(request, initTransaction.nonce)

            val supportedEncryptionMethods = assertNotNull(request.supportedEncryptionMethods())
            assertEquals(config.clientMetaData.responseEncryptionOption.encryptionMethods, supportedEncryptionMethods)
        }

    @Test
    fun `haip - signed dc_api request is initialized`(): Unit =
        runBlocking {
            assertIs<VerifierId.X509Hash>(config.verifierId)

            val initTransaction =
                VerifierApiClient
                    .loadInitDCApiTransactionTO("09-dcApi-dcql.json")
                    .copy(profile = ProfileTO.HAIP, requestType = RequestTypeTO.Signed)

            val (body, transactionId) = VerifierApiClient.initDCApiTransaction(client, initTransaction)
            assertNotNull(transactionId, "Transaction-Id header is missing")

            val requestJwt = assertNotNull(body["request"]?.jsonPrimitive?.contentOrNull, "request is not a JWT string")
            val (_, claims) = TestUtils.parseJWTIntoClaims(requestJwt)
            assertDCApiRequest(claims, initTransaction.nonce)

            val expectedOrigins = assertNotNull(claims[OpenId4VPSpec.DCAPI_EXPECTED_ORIGINS], "expected_origins is missing")
            assertTrue(expectedOrigins.toString().contains("https://verifier.example.com"))
        }
}
