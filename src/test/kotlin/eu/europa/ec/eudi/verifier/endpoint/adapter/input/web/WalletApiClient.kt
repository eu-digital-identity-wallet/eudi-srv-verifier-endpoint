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

import eu.europa.ec.eudi.verifier.endpoint.domain.RFC9101
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Assertions.assertNotNull
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec.ResponseSpecConsumer
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.BodyInserters

object WalletApiClient {

    private val log: Logger = LoggerFactory.getLogger(WalletApiClient::class.java)

    /**
     * Wallet application to Verifier Backend, get DCQL query
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "6 HTTPs GET to request_uri"
     * - (response) Internet Web Service to mDocApp, flow "7 JWS Authorisation request object [section B.3.2.1]"
     */
    fun getRequestObjectJsonResponse(client: WebTestClient, requestUri: String): JsonObject {
        val (header, payload) = getRequestObjectPair(client, requestUri)
        // debug
        TestUtils.prettyPrintJson("prettyHeader:\n", header)
        TestUtils.prettyPrintJson("prettyPayload:\n", payload)

        return payload
    }

    /**
     * Wallet application to Verifier Backend, get DCQL query
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "6 HTTPs GET to request_uri"
     * - (response) Internet Web Service to mDocApp, flow "7 JWS Authorisation request object [section B.3.2.1]"
     */
    fun getRequestObject(client: WebTestClient, requestUri: String) {
        val (header, payload) = getRequestObjectPair(client, requestUri)

        // debug
        TestUtils.prettyPrintJson("WalletApi.getRequestObject.prettyHeader:\n", header)
        TestUtils.prettyPrintJson("WalletApi.getRequestObject.prettyPayload:\n", payload)
    }

    /**
     * private helper function to get the request object response as a pair of strings (header, payload)
     */
    private fun getRequestObjectPair(client: WebTestClient, requestUri: String): Pair<JsonObject, JsonObject> {
        // update the request_uri to point to the local server
        val relativeRequestUri = requestUri.removePrefix("http://localhost:0")
        log.info("relative request_uri: $relativeRequestUri")

        // get the DCQL query
        val getResponse = client.get()
            .uri(relativeRequestUri)
            .accept(MediaType.parseMediaType(RFC9101.REQUEST_OBJECT_MEDIA_TYPE))
            .exchange()
            .expectStatus().isOk()
            .expectBody<String>().returnResult()

        assertNotNull(getResponse.responseBody, "getResponseString is null")
        log.info("response: $getResponse.responseBody")

        return TestUtils.parseJWTIntoClaims(getResponse.responseBody!!)
    }

    /**
     * Wallet application to Verifier Backend, submit wallet response
     *
     * As per OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Wallet to Verifier Response endpoint, flow "(5) Authorisation Response (VP Token, state)"
     * - (response) Verifier ResponseEndpoint to Wallet, flow "(6) Response (redirect_uri with response_code)"
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "12 HTTPs POST to response_uri [section B.3.2.2]
     * - (response) Internet Web Service to mDocApp, flow "14 OK: HTTP 200 with redirect_uri"
     */
    fun directPost(
        client: WebTestClient,
        requestId: RequestId,
        formEncodedBody: MultiValueMap<String, Any>,
        vararg consumers: ResponseSpecConsumer,
    ) {
        client.post()
            .uri { builder -> builder.path(WalletApi.WALLET_RESPONSE_PATH).build(requestId.value) }
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(formEncodedBody))
            .exchange()
            // then
            .expectAll(*consumers)
            .expectStatus().isOk()
    }

    /**
     * Wallet application to Verifier Backend, submit wallet response
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw">OpenId4vp Response Mode "direct_post.jwt</a>
     */
    fun directPostJwt(
        client: WebTestClient,
        requestId: RequestId,
        formEncodedBody: MultiValueMap<String, Any>,
    ) {
        client.post()
            .uri { builder -> builder.path(WalletApi.WALLET_RESPONSE_PATH).build(requestId.value) }
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(formEncodedBody))
            .exchange()
            // then
            .expectStatus().isOk()
    }
}
