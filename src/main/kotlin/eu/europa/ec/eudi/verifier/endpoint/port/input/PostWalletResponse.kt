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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.raise.Raise
import arrow.core.raise.context.bind
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.effect
import arrow.core.raise.either
import arrow.core.raise.recover
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.Submitted
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyEncryptedResponse
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Represent the Authorization Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val vpToken: JsonObject? = null,
)

sealed interface AuthorisationResponse {
    data class DirectPost(
        val response: AuthorisationResponseTO,
    ) : AuthorisationResponse

    data class DirectPostJwt(
        val encryptedResponse: Jwt,
    ) : AuthorisationResponse

    data class DcApiJwt(
        val encryptedResponse: Jwt,
    ) : AuthorisationResponse
}

private fun AuthorisationResponse.DirectPost.isErrorResponse(): Boolean = null != response.error

sealed interface WalletResponseValidationError {
    data object PresentationNotFound : WalletResponseValidationError

    data class UnexpectedResponseMode(
        val requestId: RequestId?,
        val expected: ResponseModeOption,
        val actual: ResponseModeOption,
    ) : WalletResponseValidationError

    data object PresentationNotInExpectedState : WalletResponseValidationError

    data object IncorrectState : WalletResponseValidationError

    data class InvalidVpToken(
        val message: String,
        val cause: Throwable? = null,
    ) : WalletResponseValidationError

    data object MissingVpToken : WalletResponseValidationError

    data object RequiredCredentialSetNotSatisfied : WalletResponseValidationError

    data class InvalidEncryptedResponse(
        val error: Exception,
    ) : WalletResponseValidationError

    sealed interface HAIPValidationError : WalletResponseValidationError {
        data object DeviceResponseContainsMoreThanOneMDoc : HAIPValidationError

        data class UnsupportedMsoRevocationMechanism(
            val used: Set<String>,
            val allowed: Set<String>,
        ) : HAIPValidationError

        data object SdJwtVcMustUseTokenStatusList : HAIPValidationError
    }
}

context(_: Raise<WalletResponseValidationError>)
private suspend fun AuthorisationResponseTO.toDomain(
    presentation: RequestObjectRetrieved,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
    vpFormatsSupported: VpFormatsSupported,
): WalletResponse {
    suspend fun requiredVerifiablePresentations(): VerifiablePresentations =
        verifiablePresentations(
            presentation,
            validateVerifiablePresentation,
            vpFormatsSupported,
        )

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }
    return maybeError ?: WalletResponse.VpToken(requiredVerifiablePresentations())
}

context(_: Raise<WalletResponseValidationError>)
private suspend fun AuthorisationResponseTO.verifiablePresentations(
    presentation: RequestObjectRetrieved,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
    vpFormatsSupported: VpFormatsSupported,
): VerifiablePresentations {
    ensureNotNull(vpToken) { MissingVpToken }

    suspend fun JsonObject.toVerifiablePresentations(): Map<QueryId, List<VerifiablePresentation>> {
        val vpToken =
            try {
                Json.decodeFromJsonElement<Map<QueryId, List<JsonElement>>>(this)
            } catch (e: Exception) {
                raise(InvalidVpToken("Failed to decode vp_token", e))
            }

        val credentialQueries =
            presentation.query.credentials.value
                .associateBy { it.id }
        return vpToken.mapValues { (queryId, value) ->
            val format =
                credentialQueries[queryId]?.format
                    ?: raise(
                        InvalidVpToken(
                            "vp_token references non-existing Credential Query",
                            null,
                        ),
                    )
            val unvalidatedVerifiablePresentations = value.map { it.toVerifiablePresentation(format) }
            val applicableTransactionData =
                presentation.transactionData
                    ?.filter { queryId.value in it.credentialIds }
                    ?.toNonEmptyListOrNull()
            ensure(vpFormatsSupported.supports(format)) {
                InvalidVpToken(
                    "vp_token contains a Verifiable Presentation in an unsupported format",
                    null,
                )
            }
            unvalidatedVerifiablePresentations.map {
                validateVerifiablePresentation(
                    presentation,
                    it,
                    applicableTransactionData,
                )
            }
        }
    }

    val verifiablePresentations = vpToken.toVerifiablePresentations()
    ensure(presentation.query.satisfiedBy(verifiablePresentations)) {
        RequiredCredentialSetNotSatisfied
    }

    return VerifiablePresentations(verifiablePresentations)
}

context(_: Raise<WalletResponseValidationError>)
private fun JsonElement.toVerifiablePresentation(format: Format): VerifiablePresentation {
    fun JsonElement.asString(): VerifiablePresentation.Str {
        val element = this@asString
        ensure(element is JsonPrimitive && element.isString) {
            InvalidVpToken("vp_token contains a non-string element", null)
        }
        return VerifiablePresentation.Str(element.content, format)
    }

    fun JsonElement.asStringOrObject(): VerifiablePresentation =
        when (val element = this@asStringOrObject) {
            is JsonPrimitive -> {
                ensure(
                    element.isString,
                ) { InvalidVpToken("vp_token contains a non-string element", null) }
                VerifiablePresentation.Str(element.content, format)
            }

            is JsonObject -> {
                VerifiablePresentation.Json(element, format)
            }

            else -> {
                raise(
                    InvalidVpToken(
                        "vp_token must contain either json strings, or json objects",
                        null,
                    ),
                )
            }
        }

    val element = this@toVerifiablePresentation
    return when (format) {
        Format.MsoMdoc -> element.asString()
        Format.SdJwtVc -> element.asStringOrObject()
        else -> element.asStringOrObject()
    }
}

@Serializable
data class WalletResponseAcceptedTO(
    @SerialName(OpenId4VPSpec.REDIRECT_URI) val redirectUri: String,
)

/**
 * This is use-case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
fun interface PostWalletResponse {
    context(_: Raise<WalletResponseValidationError>)
    suspend operator fun invoke(
        requestId: RequestId,
        walletResponse: AuthorisationResponse,
    ): WalletResponseAcceptedTO?
}

private val log = LoggerFactory.getLogger(PostWalletResponse::class.java)

class PostWalletResponseLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val verifyEncryptedResponse: VerifyEncryptedResponse,
    private val clock: Clock,
    private val verifierConfig: VerifierConfig,
    private val generateResponseCode: GenerateResponseCode,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val validateVerifiablePresentation: ValidateVerifiablePresentation,
) : PostWalletResponse {
    context(_: Raise<WalletResponseValidationError>)
    override suspend operator fun invoke(
        requestId: RequestId,
        walletResponse: AuthorisationResponse,
    ): WalletResponseAcceptedTO? {
        log.debug(requestId, walletResponse)

        val presentation = loadPresentation(requestId)
        ensure(presentation is RequestObjectRetrieved) {
            PresentationNotInExpectedState
        }
        log.debug(presentation, walletResponse)

        val responseObject = responseObject(walletResponse, presentation)
        log.info(presentation.id, responseObject)

        return effect {
            val (submitted, accepted) = submit(presentation, responseObject)
            logWalletResponsePosted(submitted, accepted)
            accepted
        }.recover { cause ->
            logFailure(presentation, responseObject, cause)
            raise(cause)
        }.bind()
    }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Pair<Submitted, WalletResponseAcceptedTO?> {
        // Submit the response
        val submitted =
            doSubmit(presentation, responseObject).also { storePresentation(it) }

        val accepted =
            when (val channel = presentation.channel) {
                is Channel.OverHttp -> {
                    when (val getWalletResponseMethod = channel.getWalletResponseMethod) {
                        is GetWalletResponseMethod.Redirect -> {
                            with(createQueryWalletResponseRedirectUri) {
                                requireNotNull(submitted.responseCode) { "ResponseCode expected in Submitted state but not found" }
                                val redirectUri = getWalletResponseMethod.redirectUri(submitted.responseCode)
                                WalletResponseAcceptedTO(redirectUri.toString())
                            }
                        }

                        GetWalletResponseMethod.Poll -> {
                            null
                        }
                    }
                }

                is Channel.OverDcApi -> {
                    null
                }
            }
        return submitted to accepted
    }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun loadPresentation(requestId: RequestId): Presentation {
        val presentation = loadPresentationByRequestId(requestId)
        return ensureNotNull(presentation) { PresentationNotFound }
    }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun responseObject(
        walletResponse: AuthorisationResponse,
        presentation: RequestObjectRetrieved,
    ): AuthorisationResponseTO =
        when (val channel = presentation.channel) {
            is Channel.OverHttp -> {
                when (val responseMode = channel.responseMode) {
                    ResponseMode.OverHttp.DirectPost -> {
                        ensure(walletResponse is AuthorisationResponse.DirectPost) {
                            UnexpectedResponseMode(
                                presentation.channel.requestId,
                                expected = ResponseModeOption.DirectPost,
                                actual = walletResponse.responseModeOption,
                            )
                        }
                        walletResponse.response
                    }

                    is ResponseMode.OverHttp.DirectPostJwt -> {
                        when (walletResponse) {
                            is AuthorisationResponse.DirectPost -> {
                                ensure(walletResponse.isErrorResponse()) {
                                    UnexpectedResponseMode(
                                        presentation.channel.requestId,
                                        expected = ResponseModeOption.DirectPostJwt,
                                        actual = ResponseModeOption.DirectPost,
                                    )
                                }
                                walletResponse.response
                            }

                            is AuthorisationResponse.DirectPostJwt -> {
                                verifyEncryptedResponse(
                                    ephemeralResponseEncryptionKey = responseMode.ephemeralResponseEncryptionKey,
                                    encryptedResponse = walletResponse.encryptedResponse,
                                    apv = presentation.nonce,
                                )
                            }

                            else -> {
                                raise(
                                    UnexpectedResponseMode(
                                        presentation.channel.requestId,
                                        expected = ResponseModeOption.DirectPostJwt,
                                        actual = walletResponse.responseModeOption,
                                    ),
                                )
                            }
                        }
                    }
                }
            }

            is Channel.OverDcApi -> {
                when (val responseMode = channel.responseMode) {
                    is ResponseMode.OverDcApi.DcApiJwt -> {
                        when (walletResponse) {
                            is AuthorisationResponse.DcApiJwt -> {
                                verifyEncryptedResponse(
                                    ephemeralResponseEncryptionKey = responseMode.ephemeralResponseEncryptionKey,
                                    encryptedResponse = walletResponse.encryptedResponse,
                                    apv = presentation.nonce,
                                )
                            }

                            else -> {
                                raise(
                                    UnexpectedResponseMode(
                                        null,
                                        expected = ResponseModeOption.DcApiJwt,
                                        actual = walletResponse.responseModeOption,
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        }

    context(_: Raise<WalletResponseValidationError>)
    private suspend fun doSubmit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Submitted {
        // add the wallet response to the presentation
        val walletResponse =
            responseObject.toDomain(
                presentation,
                validateVerifiablePresentation,
                verifierConfig.clientMetaData.vpFormatsSupported,
            )

        val responseCode =
            when (val channel = presentation.channel) {
                is Channel.OverDcApi -> {
                    null
                }

                is Channel.OverHttp -> {
                    // Verify response `state` is RequestId
                    ensure(presentation.channel.requestId.value == responseObject.state) { IncorrectState }
                    when (channel.getWalletResponseMethod) {
                        GetWalletResponseMethod.Poll -> null
                        is GetWalletResponseMethod.Redirect -> generateResponseCode()
                    }
                }
            }

        return either { presentation.submit(clock, walletResponse, responseCode) }
            .mapLeft { IllegalArgumentException(it) }
            .getOrThrow()
    }

    private suspend fun logWalletResponsePosted(
        p: Submitted,
        accepted: WalletResponseAcceptedTO?,
    ) {
        val event =
            PresentationEvent.WalletResponsePosted(p.id, p.submittedAt, p.walletResponse.toTO(), accepted)
        publishPresentationEvent(event)
    }

    private suspend fun logFailure(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
        cause: WalletResponseValidationError,
    ) {
        val event =
            PresentationEvent.WalletFailedToPostResponse(
                presentation.id,
                clock.now(),
                cause,
                responseObject.vpToken,
            )
        publishPresentationEvent(event)
    }
}

private fun DCQL.satisfiedBy(response: Map<QueryId, List<VerifiablePresentation>>): Boolean =
    credentialSets
        ?.value
        ?.filter { credentialSet -> credentialSet.requiredOrDefault }
        ?.map { credentialSet -> credentialSet.options.any { option -> response.keys.containsAll(option.value) } }
        ?.fold(true, Boolean::and)
        ?: response.keys.containsAll(credentials.ids)

private val AuthorisationResponse.responseModeOption: ResponseModeOption
    get() =
        when (this) {
            is AuthorisationResponse.DirectPost -> ResponseModeOption.DirectPost
            is AuthorisationResponse.DirectPostJwt -> ResponseModeOption.DirectPostJwt
            is AuthorisationResponse.DcApiJwt -> ResponseModeOption.DcApiJwt
        }
private val AuthorisationResponse.encryptedResponseOrNull: Jwt?
    get() =
        when (this) {
            is AuthorisationResponse.DirectPost -> null
            is AuthorisationResponse.DirectPostJwt -> encryptedResponse
            is AuthorisationResponse.DcApiJwt -> encryptedResponse
        }

private val AuthorisationResponse.vpTokenOrNull: JsonObject?
    get() =
        when (this) {
            is AuthorisationResponse.DirectPost -> response.vpToken
            is AuthorisationResponse.DirectPostJwt -> null
            is AuthorisationResponse.DcApiJwt -> null
        }

private val RequestObjectRetrieved.ephemeralResponseEncryptionKeyOrNull: JWK?
    get() =
        when (val channel = this.channel) {
            is Channel.OverHttp -> {
                when (val responseMode = channel.responseMode) {
                    ResponseMode.OverHttp.DirectPost -> null
                    is ResponseMode.OverHttp.DirectPostJwt -> responseMode.ephemeralResponseEncryptionKey
                }
            }

            is Channel.OverDcApi -> {
                when (val responseMode = channel.responseMode) {
                    is ResponseMode.OverDcApi.DcApiJwt -> responseMode.ephemeralResponseEncryptionKey
                }
            }
        }

private fun Logger.debug(
    requestId: RequestId,
    walletResponse: AuthorisationResponse,
) {
    debug(
        "RequestId({}):: Wallet posted response. \nEncrypted response: '{}', \nVP Token: '{}'",
        requestId.value,
        walletResponse.encryptedResponseOrNull,
        walletResponse.vpTokenOrNull,
    )
}

private fun Logger.debug(
    presentation: RequestObjectRetrieved,
    walletResponse: AuthorisationResponse,
) {
    debug(
        "TransactionId({}):: Wallet posted response. \nEncrypted response: '{}', \nDecryption Key: '{}', \nVP Token: '{}'",
        presentation.id.value,
        walletResponse.encryptedResponseOrNull,
        presentation.ephemeralResponseEncryptionKeyOrNull?.toJSONString(),
        walletResponse.vpTokenOrNull,
    )
}

private fun Logger.info(
    transactionId: TransactionId,
    authorizationResponse: AuthorisationResponseTO,
) {
    info(
        "TransactionId({}):: Wallet posted response. \nVP Token: '{}'",
        transactionId.value,
        authorizationResponse.vpToken,
    )
}
