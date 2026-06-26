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

import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApi.Companion.TRANSACTION_ID_HEADER
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseCode
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitDcApiTransactionResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitDcApiTransactionTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.Output
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.EntityExchangeResult
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody

object VerifierApiClient {
    private val log: Logger = LoggerFactory.getLogger(VerifierApiClient::class.java)

    fun loadInitTransactionTO(testResource: String): InitTransactionTO = Json.decodeFromString(TestUtils.loadResource(testResource))

    fun loadInitDCApiTransactionTO(testResource: String): InitDcApiTransactionTO =
        Json.decodeFromString(TestUtils.loadResource(testResource))

    /**
     * Initializes a Digital Credentials API (DC API) Transaction.
     *
     * Posts an [InitDcApiTransactionTO] to [VerifierApi.INIT_TRANSACTION_PATH_DC_API] and returns
     * the raw response body parsed as a [InitDcApiTransactionResponseTO] together with the value of the
     * [TRANSACTION_ID_HEADER] response header.
     */
    fun initDCApiTransaction(
        client: WebTestClient,
        initDCApiTransactionTO: InitDcApiTransactionTO,
    ): Pair<InitDcApiTransactionResponseTO, String> {
        val result =
            client
                .post()
                .uri(VerifierApi.INIT_TRANSACTION_PATH_DC_API)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(initDCApiTransactionTO)
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody<InitDcApiTransactionResponseTO>()
                .returnResult()

        val transactionId = checkNotNull(result.responseHeaders.getFirst(TRANSACTION_ID_HEADER))
        val body = checkNotNull(result.responseBody)
        log.info("DC API init response body:\n$body")
        return body to transactionId
    }

    fun initTransaction(
        client: WebTestClient,
        initTransactionTO: InitTransactionTO,
        output: Output = Output.Json,
    ): InitTransactionResponse {
        val accept =
            when (output) {
                Output.Json -> MediaType.APPLICATION_JSON
                Output.QrCode -> MediaType.IMAGE_PNG
            }

        val responseSpec =
            client
                .post()
                .uri(VerifierApi.INIT_TRANSACTION_PATH_V2)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(accept)
                .bodyValue(initTransactionTO)
                .exchange()

        return when (output) {
            Output.Json -> {
                responseSpec
                    .expectStatus()
                    .isOk()
                    .expectBody<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>()
                    .returnResult()
                    .responseBody!!
            }

            Output.QrCode -> {
                val response =
                    responseSpec
                        .expectStatus()
                        .isOk()
                        .expectBody<ByteArray>()
                        .returnResult()

                val qrCode = checkNotNull(response.responseBody)
                val transactionId = checkNotNull(response.responseHeaders.getFirst(TRANSACTION_ID_HEADER))
                val authorizationRequestUri = checkNotNull(response.responseHeaders.getFirst(VerifierApi.AUTHORIZATION_REQUEST_URI_HEADER))

                InitTransactionResponse.QrCode(qrCode, transactionId, authorizationRequestUri)
            }
        }
    }

    /**
     * Verifier application to Verifier Backend, get authorisation response
     *
     * As per OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Verifier to Verifier Response endpoint, flow "(8) fetch response data (transaction-id, response_code)"
     * - (response) Verifier ResponseEndpoint to Verifier, flow "(9) response data (VP Token, Presentation Submission)"
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mdocVerification application Internet frontend to Internet Web Service, flow "18 HTTPs POST to response_uri [section B.3.2.2]
     * - (response) Internet Web Service to mdocVerification application Internet frontend, flow "20 return status and conditionally return data"
     */
    fun getWalletResponse(
        client: WebTestClient,
        presentationId: TransactionId,
        responseCode: ResponseCode? = null,
    ): WalletResponseTO? {
        val walletResponseUri =
            VerifierApi.WALLET_RESPONSE_PATH.replace("{transactionId}", presentationId.value) +
                (responseCode?.let { "?response_code=${it.value}" } ?: "")

        // when
        val responseSpec =
            client
                .get()
                .uri(walletResponseUri)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
        val returnResult = responseSpec.expectBody<WalletResponseTO>().returnResult()
        returnResult.status.also { log.info("response status: $it") }
        returnResult.responseHeaders.also { log.info("response headers: $it") }

        // then
        assertEquals(HttpStatus.OK, returnResult.status)

        return returnResult.responseBody?.also { responseBody ->
            log.info("response body:\n$responseBody")
        }
    }

    fun getWalletResponseNoValidation(
        client: WebTestClient,
        transactionId: TransactionId,
        responseCode: ResponseCode? = null,
    ): EntityExchangeResult<WalletResponseTO> {
        val walletResponseUri =
            VerifierApi.WALLET_RESPONSE_PATH.replace("{transactionId}", transactionId.value) +
                (responseCode?.let { "?response_code=${it.value}" } ?: "")

        // when
        val responseSpec =
            client
                .get()
                .uri(walletResponseUri)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
        return responseSpec.expectBody<WalletResponseTO>().returnResult()
    }
}
