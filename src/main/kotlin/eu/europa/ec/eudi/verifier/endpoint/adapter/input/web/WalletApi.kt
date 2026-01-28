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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*
import org.springframework.web.util.DefaultUriBuilderFactory

private val REQUEST_OBJECT_MEDIA_TYPE = MediaType.parseMediaType(RFC9101.REQUEST_OBJECT_MEDIA_TYPE)

/**
 * The WEB API available to the wallet
 */
class WalletApi(
    private val retrieveRequestObject: RetrieveRequestObject,
    private val postWalletResponse: PostWalletResponse,
    private val signingKey: JWK,
) {

    private val logger: Logger = LoggerFactory.getLogger(WalletApi::class.java)

    /**
     * The routes available to the wallet
     */
    val route = coRouter {
        GET(REQUEST_JWT_PATH, this@WalletApi::handleRetrieveRequestObject)
        POST(
            REQUEST_JWT_PATH,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(REQUEST_OBJECT_MEDIA_TYPE),
            this@WalletApi::handleRetrieveRequestObject,
        )
        POST(
            WALLET_RESPONSE_PATH,
            this@WalletApi::handlePostWalletResponse,
        )
        GET(GET_PUBLIC_JWK_SET_PATH) { _ -> handleGetPublicJwkSet() }
    }

    /**
     * Handles a request placed by the wallet, input order to obtain
     * the Request Object of the presentation.
     * If found, the Request Object will be returned as JWT
     */
    private suspend fun handleRetrieveRequestObject(req: ServerRequest): ServerResponse {
        suspend fun ServerRequest.invocationMethod(): RetrieveRequestObjectMethod =
            when (method()) {
                HttpMethod.GET -> RetrieveRequestObjectMethod.Get
                HttpMethod.POST -> {
                    val form = awaitFormData()
                    RetrieveRequestObjectMethod.Post(
                        walletMetadata = form.getFirst(OpenId4VPSpec.WALLET_METADATA),
                        walletNonce = form.getFirst(OpenId4VPSpec.WALLET_NONCE),
                    )
                }
                else -> error("Allowed HTTP Method: GET, POST")
            }

        suspend fun requestObjectFound(jwt: String) = ok().contentType(REQUEST_OBJECT_MEDIA_TYPE).bodyValueAndAwait(jwt)

        val requestId = req.requestId()
        val invocationMethod = req.invocationMethod()

        logger.info("Handling GetRequestObject for ${requestId.value} ...")
        val result = retrieveRequestObject(requestId, invocationMethod)
        return result.fold(
            ifRight = { requestObjectFound(it) },
            ifLeft = {
                val status = when (it) {
                    RetrieveRequestObjectError.PresentationNotFound -> HttpStatus.NOT_FOUND
                    else -> HttpStatus.BAD_REQUEST
                }
                status(status).buildAndAwait()
            },
        )
    }

    /**
     * Handles a POST request placed by the wallet, input order to submit
     * the [AuthorisationResponse], containing the presentation_submission
     * and the verifiableCredentials
     */
    private suspend fun handlePostWalletResponse(req: ServerRequest): ServerResponse = try {
        logger.info("Handling PostWalletResponse ...")
        val requestId = req.requestId()
        val walletResponse = req.awaitFormData().walletResponse()
        postWalletResponse(requestId, walletResponse).fold(
            ifRight = { response ->
                logger.info("PostWalletResponse processed")
                if (response == null) {
                    logger.info("Verifier UI will poll for Wallet Response")
                    ok().json().bodyValueAndAwait(JsonObject(emptyMap()))
                } else {
                    logger.info("Wallet must redirect to ${response.redirectUri}")
                    ok().json().bodyValueAndAwait(response)
                }
            },
            ifLeft = { error ->
                logger.error("$error while handling post of wallet response ")
                badRequest().json().bodyValueAndAwait(error.toJson())
            },
        )
    } catch (t: SerializationException) {
        logger.error("While handling post of wallet response failed to decode JSON", t)
        badRequest().buildAndAwait()
    }

    private suspend fun handleGetPublicJwkSet(): ServerResponse {
        logger.info("Handling GetPublicJwkSet ...")
        val publicJwkSet = JWKSet(signingKey).toJSONObject(true)
        return ok()
            .contentType(MediaType.parseMediaType(JWKSet.MIME_TYPE))
            .bodyValueAndAwait(publicJwkSet)
    }

    companion object {
        const val GET_PUBLIC_JWK_SET_PATH = "/wallet/public-keys.json"

        /**
         * Path template for the route for
         * getting the presentation's request object
         */
        const val REQUEST_JWT_PATH = "/wallet/request.jwt/{requestId}"

        /**
         * Path template for the route for
         * posting the Authorisation Response
         */
        const val WALLET_RESPONSE_PATH = "/wallet/direct_post/{requestId}"

        /**
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

        private fun MultiValueMap<String, String>.walletResponse(): AuthorisationResponse {
            fun directPost(): AuthorisationResponse.DirectPost {
                fun String.toJsonObject(): JsonObject = Json.decodeFromString<JsonObject>(this)

                return AuthorisationResponseTO(
                    state = getFirst("state"),
                    vpToken = getFirst("vp_token")?.toJsonObject(),
                    error = getFirst("error"),
                    errorDescription = getFirst("error_description"),
                ).run { AuthorisationResponse.DirectPost(this) }
            }

            fun directPostJwt() = getFirst("response")?.let { jwt ->
                AuthorisationResponse.DirectPostJwt(jwt)
            }

            return directPostJwt() ?: directPost()
        }

        fun requestJwtByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = REQUEST_JWT_PATH)

        fun publicJwkSet(baseUrl: String): EmbedOption.ByReference<Any> = EmbedOption.ByReference { _ ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(GET_PUBLIC_JWK_SET_PATH)
                .build()
                .toURL()
        }

        fun directPost(baseUrl: String): PresentationRelatedUrlBuilder<RequestId> = {
            DefaultUriBuilderFactory(baseUrl)
                .uriString(WALLET_RESPONSE_PATH)
                .build(it.value)
                .toURL()
        }

        private fun urlBuilder(
            baseUrl: String,
            pathTemplate: String,
        ) = EmbedOption.byReference<RequestId> { requestId ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(pathTemplate)
                .build(requestId.value)
                .toURL()
        }

        private fun WalletResponseValidationError.toJson(): JsonObject = buildJsonObject {
            when (this@toJson) {
                WalletResponseValidationError.IncorrectState -> {
                    put("error", "IncorrectState")
                    put("description", "Wallet responded with a 'state' that does not match the expected one.")
                }
                is WalletResponseValidationError.InvalidEncryptedResponse -> {
                    put("error", "InvalidEncryptedResponse")
                    put("description", this@toJson.error.message)
                    put("cause", this@toJson.error.cause?.message)
                }
                WalletResponseValidationError.InvalidPresentationSubmission -> {
                    put("error", "InvalidPresentationSubmission")
                    put("description", "The 'presentation_submission' posted by wallet does not match vp_token")
                }
                is WalletResponseValidationError.InvalidVpToken -> {
                    put("error", "InvalidVpToken")
                    put("description", this@toJson.message)
                    this@toJson.cause?.let { put("cause", message) }
                }
                WalletResponseValidationError.MissingVpToken -> {
                    put("error", "MissingVpToken")
                    put("description", "Expected 'vp_token' to be posted by wallet but was not.")
                }
                WalletResponseValidationError.PresentationNotFound -> {
                    put("error", "PresentationNotFound")
                    put("description", "The referenced presentation transaction does not exist or has expired.")
                }
                WalletResponseValidationError.PresentationNotInExpectedState -> {
                    put("error", "PresentationNotInExpectedState")
                    put("description", "The referenced presentation transaction is not in state to accept wallet response.")
                }
                WalletResponseValidationError.RequiredCredentialSetNotSatisfied -> {
                    put("error", "RequiredCredentialSetNotSatisfied")
                    put("description", "One or more of the required clauses of the DCQL presentation query was not answered.")
                }
                is WalletResponseValidationError.UnexpectedResponseMode -> {
                    put("error", "UnexpectedResponseMode")
                    put("description", "Wallet expected to respond with ${this@toJson.expected} but responded with ${this@toJson.actual}")
                }

                WalletResponseValidationError.HAIPValidationError.DeviceResponseContainsMoreThanOneMDoc -> {
                    put("error", "HAIPValidationError.DeviceResponseContainsMoreThanOneMDoc")
                    put("description", "DeviceResponse contains more than one MDocs")
                }

                is WalletResponseValidationError.HAIPValidationError.UnsupportedMsoRevocationMechanism -> {
                    put("error", "HAIPValidationError.UnsupportedMsoRevocationMechanism")
                    put(
                        "description",
                        "MSO uses unsupported revocation mechanisms. Used: '${used.joinToString()}', allowed: '${allowed.joinToString()}'",
                    )
                }

                WalletResponseValidationError.HAIPValidationError.SdJwtVcMustUseTokenStatusList -> {
                    put("error", "HAIPValidationError.SdJwtVcMustUseTokenStatusList")
                    put("description", "SD-JWT VC must use Token Status List as revocation mechanism")
                }
            }
        }
    }
}
