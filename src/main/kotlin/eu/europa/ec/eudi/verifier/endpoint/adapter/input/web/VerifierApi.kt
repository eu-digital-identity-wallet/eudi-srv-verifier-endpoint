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

import arrow.core.raise.effect
import arrow.core.raise.fold
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.WalletApi.Companion.toJson
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.http.MediaType.IMAGE_PNG
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*
import kotlin.jvm.optionals.getOrNull

internal class VerifierApi(
    private val initTransaction: InitTransaction,
    private val getWalletResponse: GetWalletResponse,
    private val getPresentationEvents: GetPresentationEvents,
    private val postWalletResponse: PostWalletResponse,
) {
    private val logger: Logger = LoggerFactory.getLogger(VerifierApi::class.java)
    val route =
        coRouter {
            POST(
                INIT_TRANSACTION_PATH,
                contentType(APPLICATION_JSON) and accept(APPLICATION_JSON, IMAGE_PNG),
            ) { request -> handleInitTransaction(request, VerifierApiVersion.V1) }
            POST(
                INIT_TRANSACTION_PATH_V2,
                contentType(APPLICATION_JSON) and accept(APPLICATION_JSON, IMAGE_PNG),
            ) { request -> handleInitTransaction(request, VerifierApiVersion.V2) }
            POST(
                INIT_TRANSACTION_PATH_DC_API,
                contentType(APPLICATION_JSON) and accept(APPLICATION_JSON),
            ) { request -> handleInitDCApiTransaction(request) }

            POST(
                DC_API_WALLET_RESPONSE_PATH,
                contentType(APPLICATION_FORM_URLENCODED) and accept(APPLICATION_JSON),
            ) { request -> handlePostDCApiWalletResponse(request) }

            GET(WALLET_RESPONSE_PATH, accept(APPLICATION_JSON), this@VerifierApi::handleGetWalletResponse)
            GET(EVENTS_RESPONSE_PATH, accept(APPLICATION_JSON), this@VerifierApi::handleGetPresentationEvents)
        }

    private suspend fun handleInitTransaction(
        request: ServerRequest,
        version: VerifierApiVersion,
    ): ServerResponse =
        effect {
            val accept = request.headers().accept()
            val output =
                when {
                    IMAGE_PNG in accept -> Output.QrCode
                    else -> Output.Json
                }
            val input = request.awaitBody<InitTransactionTO>().copy(output = output)

            logger.info("Handling InitTransaction nonce=${input.nonce} ... ")
            initTransaction(input)
        }.fold(
            transform = {
                when (it) {
                    is InitTransactionResponse.JwtSecuredAuthorizationRequestTO -> {
                        logger.info("Initiated transaction tx ${it.transactionId}")
                        val response =
                            when (version) {
                                VerifierApiVersion.V1 -> JwtSecuredAuthorizationRequestV1TO.from(it)
                                VerifierApiVersion.V2 -> it
                            }
                        ok()
                            .json()
                            .header(TRANSACTION_ID_HEADER, it.transactionId)
                            .apply {
                                if (VerifierApiVersion.V2 == version) {
                                    header(AUTHORIZATION_REQUEST_URI_HEADER, it.authorizationRequestUri)
                                }
                            }.bodyValueAndAwait(response)
                    }

                    is InitTransactionResponse.QrCode -> {
                        logger.info("Initiated transaction with qr image")
                        ok()
                            .contentType(IMAGE_PNG)
                            .header(TRANSACTION_ID_HEADER, it.transactionId)
                            .header(AUTHORIZATION_REQUEST_URI_HEADER, it.authorizationRequestUri)
                            .bodyValueAndAwait(it.qrCode)
                    }
                }
            },
            recover = { it.asBadRequest() },
            catch = { t ->
                if (t is SerializationException) {
                    logger.warn("While handling InitTransaction", t)
                    badRequest().buildAndAwait()
                } else {
                    throw t
                }
            },
        )

    private suspend fun handleInitDCApiTransaction(request: ServerRequest): ServerResponse =
        effect {
            val input = request.awaitBody<InitDcApiTransactionTO>()

            logger.info("Handling InitDCApiTransaction nonce=${input.nonce} ... ")
            initTransaction(input)
        }.fold(
            transform = {
                ok()
                    .header(TRANSACTION_ID_HEADER, it.transactionId)
                    .json()
                    .bodyValueAndAwait(it)
            },
            recover = { it.asBadRequest() },
            catch = { t ->
                if (t is SerializationException) {
                    logger.warn("While handling InitDCApiTransaction", t)
                    badRequest().buildAndAwait()
                } else {
                    throw t
                }
            },
        )

    private suspend fun handlePostDCApiWalletResponse(req: ServerRequest): ServerResponse {
        val transactionId = req.transactionId()
        return effect {
            logger.info("Handling PostDCApiWalletResponse for tx ${transactionId.value} ...")
            val walletResponse = req.awaitFormData().walletResponse()
            postWalletResponse(PresentationLookup.ByTransactionId(transactionId), walletResponse)
        }.fold(
            transform = { ok().buildAndAwait() },
            recover = { error ->
                logger.warn("PostDCApiWalletResponse failed for tx ${transactionId.value}: $error")
                badRequest().json().bodyValueAndAwait(error.toJson())
            },
        )
    }

    private fun MultiValueMap<String, String>.walletResponse(): AuthorisationResponse {
        fun dcApi(): AuthorisationResponse.DcApi {
            fun String.toJsonObject(): JsonObject = Json.decodeFromString<JsonObject>(this)

            return AuthorisationResponseTO(
                state = getFirst("state"),
                vpToken = getFirst("vp_token")?.toJsonObject(),
                error = getFirst("error"),
                errorDescription = getFirst("error_description"),
            ).run { AuthorisationResponse.DcApi(this) }
        }

        fun dcApiJwt() =
            getFirst("response")?.let { jwt ->
                AuthorisationResponse.DcApiJwt(jwt)
            }

        return dcApiJwt() ?: dcApi()
    }

    /**
     * Handles a request placed by verifier, input order to obtain
     * the wallet authorization response
     */
    private suspend fun handleGetWalletResponse(req: ServerRequest): ServerResponse {
        suspend fun found(walletResponse: WalletResponseTO) = ok().json().bodyValueAndAwait(walletResponse)

        val transactionId = req.transactionId()
        val responseCode = req.queryParam("response_code").getOrNull()?.let { ResponseCode(it) }

        logger.info("Handling GetWalletResponse for tx ${transactionId.value} and response_code: ${responseCode?.value ?: "n/a"}. ...")
        return when (val result = getWalletResponse(transactionId, responseCode)) {
            is QueryResponse.NotFound -> notFound().buildAndAwait()
            is QueryResponse.InvalidState -> badRequest().buildAndAwait()
            is QueryResponse.Found -> found(result.value)
        }
    }

    /**
     * Handles a request placed by verifier, input order to obtain
     * presentation logs
     */
    private suspend fun handleGetPresentationEvents(req: ServerRequest): ServerResponse {
        suspend fun found(events: PresentationEventsTO) = ok().json().bodyValueAndAwait(events)

        val transactionId = req.transactionId()

        logger.info("Handling Get PresentationEvents for tx ${transactionId.value}")
        return when (val result = getPresentationEvents(transactionId)) {
            is QueryResponse.NotFound -> notFound().buildAndAwait()
            is QueryResponse.InvalidState -> badRequest().buildAndAwait()
            is QueryResponse.Found -> found(result.value)
        }
    }

    companion object {
        const val INIT_TRANSACTION_PATH = "/ui/presentations"
        const val INIT_TRANSACTION_PATH_V2 = "/ui/presentations/v2"
        const val INIT_TRANSACTION_PATH_DC_API = "/ui/presentations/dc-api"
        const val DC_API_WALLET_RESPONSE_PATH = "/ui/presentations/{transactionId}/dc-api-response"
        const val WALLET_RESPONSE_PATH = "/ui/presentations/{transactionId}"
        const val EVENTS_RESPONSE_PATH = "/ui/presentations/{transactionId}/events"

        const val TRANSACTION_ID_HEADER = "Transaction-Id"
        const val AUTHORIZATION_REQUEST_URI_HEADER = "Authorization-Request-Uri"

        /**
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.transactionId() = TransactionId(pathVariable("transactionId"))

        private suspend fun ValidationError.asBadRequest(): ServerResponse {
            val error =
                when (this) {
                    ValidationError.MissingPresentationQuery -> {
                        "MissingPresentationQuery"
                    }

                    ValidationError.MissingNonce -> {
                        "MissingNonce"
                    }

                    ValidationError.InvalidWalletResponseTemplate -> {
                        "InvalidWalletResponseTemplate"
                    }

                    ValidationError.InvalidTransactionData -> {
                        "InvalidTransactionData"
                    }

                    ValidationError.UnsupportedFormat -> {
                        "UnsupportedFormat"
                    }

                    ValidationError.InvalidIssuerChain -> {
                        "InvalidIssuerChain"
                    }

                    ValidationError.ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme -> {
                        "ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme"
                    }

                    ValidationError.InvalidAuthorizationRequestUri -> {
                        "InvalidAuthorizationRequestUri"
                    }

                    ValidationError.InvalidAuthorizationRequestScheme -> {
                        "InvalidAuthorizationRequestScheme"
                    }

                    ValidationError.HaipNotSupported.SdJwtVcOrMsoMdocMustBeSupported -> {
                        "HaipNotSupported.SdJwtVcOrMsoMdocMustBeSupported"
                    }

                    ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported -> {
                        "HaipNotSupported.JwsAlgorithmES256MustBeSupported"
                    }

                    ValidationError.HaipNotSupported.ClientIdPrefixX509HashMustBeUsed -> {
                        "HaipNotSupported.ClientIdPrefixX509HashMustBeUsed"
                    }

                    ValidationError.HaipNotSupported.SelfSignedCertificateMustNotBeUsed -> {
                        "HaipNotSupported.SelfSignedCertificateMustNotBeUsed"
                    }

                    ValidationError.HaipNotSupported.EncryptionAlgorithmECDHESMustBeSupported -> {
                        "HaipNotSupported.EncryptionAlgorithmECDHESMustBeSupported"
                    }

                    ValidationError.HaipNotSupported.EncryptionMethodsA128GCMAndA256GCMMustBeSupported -> {
                        "HaipNotSupported.EncryptionMethodsA128GCMAndA256GCMMustBeSupported"
                    }

                    ValidationError.HaipNotSupported.ResponseModeDirectPostJwtMustBeUsed -> {
                        "HaipNotSupported.ResponseModeDirectPostJwtMustBeUsed"
                    }

                    ValidationError.HaipNotSupported.AuthorizationRequestMustBeProvidedByReference -> {
                        "HaipNotSupported.AuthorizationRequestMustBeProvidedByReference"
                    }
                }
            return badRequest().json().bodyValueAndAwait(mapOf("error" to error))
        }
    }
}

private enum class VerifierApiVersion {
    V1,
    V2,
}

@Serializable
private data class JwtSecuredAuthorizationRequestV1TO(
    @Required @SerialName("transaction_id") val transactionId: String,
    @Required @SerialName(RFC6749.CLIENT_ID) val clientId: ClientId,
    @SerialName(RFC9101.REQUEST) val request: String?,
    @SerialName(RFC9101.REQUEST_URI) val requestUri: String?,
    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD) val requestUriMethod: RequestUriMethodTO?,
) {
    companion object {
        fun from(to: InitTransactionResponse.JwtSecuredAuthorizationRequestTO) =
            JwtSecuredAuthorizationRequestV1TO(
                transactionId = to.transactionId,
                clientId = to.clientId,
                request = to.request,
                requestUri = to.requestUri,
                requestUriMethod = to.requestUriMethod,
            )
    }
}
