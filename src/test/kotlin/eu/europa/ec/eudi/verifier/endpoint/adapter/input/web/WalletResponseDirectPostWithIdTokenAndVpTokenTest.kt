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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.TestMethodOrder
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.core.annotation.Order
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import kotlin.test.*

@VerifierApplicationTest([WalletResponseDirectPostWithIdTokenAndVpTokenTest.Config::class])
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.response.mode=DirectPost",
        "verifier.clientMetadata.responseEncryption.algorithm=ECDH-ES",
        "verifier.clientMetadata.responseEncryption.method=A128CBC-HS256",
    ],
)
@TestMethodOrder(OrderAnnotation::class)
internal class WalletResponseDirectPostWithIdTokenAndVpTokenTest {

    private val log: Logger = LoggerFactory.getLogger(WalletResponseDirectPostWithIdTokenAndVpTokenTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    @TestConfiguration
    internal class Config {

        @Bean
        @Primary
        fun validateVerifiablePresentation(): ValidateVerifiablePresentation = ValidateVerifiablePresentation.NoOp
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post DCQL query
     * - wallet to verifier backend, to post wallet response
     */
    @Test
    @Order(value = 1)
    fun `post wallet response (only idToken) - confirm returns 200`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-dcql.json")
        val transactionInitialized =
            assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(VerifierApiClient.initTransaction(client, initTransaction))
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val presentationId = transactionInitialized.transactionId
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("vp_token", TestUtils.loadResource("02-vpToken.json"))

        // when
        WalletApiClient.directPost(client, requestId, formEncodedBody)

        // then
        assertNotNull(presentationId)
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post DCQL query
     * - wallet to verifier backend, to post wallet response
     * - verifier to verifier backend, to get wallet response
     */
    @Test
    @Order(value = 2)
    fun `get authorisation response - confirm returns 200`() = runTest {
        fun test(
            dcqlQuery: String,
            vpToken: String,
            asserter: (WalletResponseTO) -> Unit,
        ) {
            // given
            val initTransaction = VerifierApiClient.loadInitTransactionTO(dcqlQuery)
            val transactionInitialized =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, initTransaction),
                )
            val presentationId = TransactionId(transactionInitialized.transactionId)
            val requestId =
                RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
            WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

            val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
            formEncodedBody.add("state", requestId.value)
            formEncodedBody.add("vp_token", TestUtils.loadResource(vpToken))

            WalletApiClient.directPost(client, requestId, formEncodedBody)

            // when
            val response = VerifierApiClient.getWalletResponse(client, presentationId)

            // then
            assertNotNull(response)
            asserter(response)
        }

        // Test with single Verifiable Presentation -- single JsonObject
        test("02-dcql.json", "02-vpToken.json") {
            val vpToken = assertNotNull(it.vpToken)

            val waDriverLicence = assertIs<JsonArray>(vpToken["wa_driver_license"])
            assertEquals(1, waDriverLicence.size)
            assertIs<JsonObject>(waDriverLicence[0])
        }

        // Test with multiple Verifiable Presentation -- single JsonArray that contains one JsonPrimitive and one JsonObject
        test("03-dcql.json", "03-vpToken.json") {
            val vpToken = assertNotNull(it.vpToken)
            assertEquals(2, vpToken.size)

            val employmentInput = assertIs<JsonArray>(vpToken["employment_input"])
            assertEquals(1, employmentInput.size)
            assertIs<JsonPrimitive>(employmentInput[0])

            val employmentInput2 = assertIs<JsonArray>(vpToken["employment_input_2"])
            assertEquals(1, employmentInput2.size)
            assertIs<JsonObject>(employmentInput2[0])
        }
    }

    /**
     * Verifies that a Transaction expecting a direct_post Wallet response, doesn't accept a direct_post.jwt Wallet response.
     */
    @Test
    @Order(value = 3)
    fun `with response_mode direct_post, direct_post_jwt wallet responses are rejected`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-dcql.json")
        val transactionInitialized =
            assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(VerifierApiClient.initTransaction(client, initTransaction))
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // At this point we don't generate an actual encrypted response
        // The response will be rejected before encrypted parsing/verification takes place
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("response", "response")

        // send the wallet response
        // we expect the response submission to fail
        try {
            WalletApiClient.directPostJwt(client, requestId, formEncodedBody)
            fail("Expected direct_post.jwt submission to fail for direct_post Presentation")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }

    @Test
    @Order(value = 4)
    fun `presentation with dcql query accepts dcql response`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("04-dcql.json")
        val transactionInitialized =
            assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(VerifierApiClient.initTransaction(client, initTransaction))
        val presentationId = TransactionId(transactionInitialized.transactionId)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("vp_token", TestUtils.loadResource("04-vpToken.json"))

        WalletApiClient.directPost(client, requestId, formEncodedBody)

        val response = assertNotNull(VerifierApiClient.getWalletResponse(client, presentationId))

        val vpToken = assertNotNull(response.vpToken)
        assertEquals(2, vpToken.size)

        val employmentInput = assertIs<JsonArray>(vpToken["employment_input"])
        assertEquals(1, employmentInput.size)
        assertIs<JsonPrimitive>(employmentInput[0])

        val employmentInput2 = assertIs<JsonArray>(vpToken["employment_input_2"])
        assertEquals(1, employmentInput2.size)
        assertIs<JsonObject>(employmentInput2[0])
    }

    @Test
    @Order(value = 5)
    fun `presentation with dcql query rejects dcql response when credential sets are not satisfied`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("05-dcql.json")
        val transactionInitialized =
            assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(VerifierApiClient.initTransaction(client, initTransaction))
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("vp_token", TestUtils.loadResource("04-vpToken.json"))

        try {
            WalletApiClient.directPost(client, requestId, formEncodedBody)
            fail("Expected Presentation Exchange response to be rejected for DCQL query")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }

    @Test
    @Order(value = 6)
    fun `presentation with dcql query accepts dcql response when all required credential sets are satisfied`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("05-dcql.json")
        val transactionInitialized =
            assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(VerifierApiClient.initTransaction(client, initTransaction))
        val presentationId = TransactionId(transactionInitialized.transactionId)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("vp_token", TestUtils.loadResource("05-vpToken.json"))

        WalletApiClient.directPost(client, requestId, formEncodedBody)

        val response = assertNotNull(VerifierApiClient.getWalletResponse(client, presentationId))

        val vpToken = assertNotNull(response.vpToken)
        assertEquals(3, vpToken.size)

        val employmentInput = assertIs<JsonArray>(vpToken["employment_input"])
        assertEquals(1, employmentInput.size)
        assertIs<JsonPrimitive>(employmentInput[0])

        val employmentInput2 = assertIs<JsonArray>(vpToken["employment_input_2"])
        assertEquals(1, employmentInput2.size)
        assertIs<JsonObject>(employmentInput2[0])

        val employmentInput3 = assertIs<JsonArray>(vpToken["employment_input_3"])
        assertEquals(1, employmentInput3.size)
        assertIs<JsonPrimitive>(employmentInput3[0])
    }
}
