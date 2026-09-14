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
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import kotlinx.coroutines.test.runTest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import kotlin.test.Test
import kotlin.test.assertIs

/**
 * A Verifier polling for a Wallet response has to tell apart a transient state, where the Wallet
 * has not submitted yet, from a terminal one, where the provided response_code does not match.
 * Both are Bad Request, so they are distinguished by the error code in the response body.
 */
@VerifierApplicationTest
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.defaultHttpResponseMode=DirectPost",
        "verifier.clientMetadata.responseEncryption.algorithm=ECDH-ES",
        "verifier.clientMetadata.responseEncryption.method=A128CBC-HS256",
    ],
)
internal class GetWalletResponseErrorsTest {
    @Autowired
    private lateinit var client: WebTestClient

    @Test
    fun `when the wallet has not submitted yet, the error is PresentationNotSubmitted`() =
        runTest {
            val transactionDetails =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, VerifierApiClient.loadInitTransactionTO("02-dcql.json")),
                )

            getWalletResponse(transactionDetails.transactionId)
                .expectStatus()
                .isBadRequest()
                .expectBody()
                .jsonPath("$.error")
                .isEqualTo("PresentationNotSubmitted")
        }

    @Test
    fun `when the provided response_code does not match, the error is InvalidResponseCode`() =
        runTest {
            val initTransaction =
                VerifierApiClient
                    .loadInitTransactionTO("02-dcql.json")
                    .copy(
                        redirectUriTemplate =
                            "https://client.example.org/cb?response_code=" +
                                CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER,
                    )
            val transactionDetails =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, initTransaction),
                )
            WalletApiClient.retrieveRequestObjectResponse(client, transactionDetails.requestUri!!)

            // Submit a response, so that the presentation leaves the not-submitted state and a
            // response code is issued. The content of the response does not matter here.
            val requestId = RequestId(transactionDetails.requestUri.removePrefix("http://localhost:0/wallet/request.jwt/"))
            val walletResponse =
                LinkedMultiValueMap<String, Any>().apply {
                    add("state", requestId.value)
                    add("error", "access_denied")
                }
            WalletApiClient.directPost(client, requestId, walletResponse)

            getWalletResponse(transactionDetails.transactionId, responseCode = "not-the-issued-response-code")
                .expectStatus()
                .isBadRequest()
                .expectBody()
                .jsonPath("$.error")
                .isEqualTo("InvalidResponseCode")
        }

    private fun getWalletResponse(
        transactionId: String,
        responseCode: String? = null,
    ): WebTestClient.ResponseSpec {
        val uri =
            VerifierApi.WALLET_RESPONSE_PATH.replace("{transactionId}", transactionId) +
                (responseCode?.let { "?response_code=$it" } ?: "")
        return client
            .get()
            .uri(uri)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
    }
}
