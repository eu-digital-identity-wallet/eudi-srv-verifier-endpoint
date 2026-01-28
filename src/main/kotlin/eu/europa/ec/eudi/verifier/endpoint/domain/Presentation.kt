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

import arrow.core.Either
import arrow.core.NonEmptyList
import kotlinx.serialization.json.JsonObject
import java.security.cert.X509Certificate
import kotlin.time.Instant

@JvmInline
value class TransactionId(val value: String) {
    init {
        require(value.isNotBlank())
    }
}

/**
 * This is an identifier of the [Presentation]
 * which is communicated to the wallet as <em>state</em>.
 * As such, it is being used to correlate an authorization response
 * send from wallet with a [Presentation]
 */
@JvmInline
value class RequestId(val value: String) {
    init {
        require(value.isNotBlank())
    }
}

@JvmInline
value class Nonce(val value: String) {
    init {
        require(value.isNotBlank())
    }
}

typealias Jwt = String

/**
 * Represents what the [Presentation] is asking
 * from the wallet
 */
data class VpTokenRequest(
    val query: DCQL,
    val transactionData: NonEmptyList<TransactionData>?,
)

sealed interface VerifiablePresentation {
    val format: Format

    data class Str(val value: String, override val format: Format) : VerifiablePresentation {
        init {
            require(value.isNotBlank()) { "VpToken cannot be blank" }
        }
    }

    data class Json(val value: JsonObject, override val format: Format) : VerifiablePresentation {
        init {
            require(value.isNotEmpty()) { "VpToken must contain claims" }
        }
    }
}

/**
 * The Wallet's response to a 'vp_token' request.
 */
@JvmInline
value class VerifiablePresentations(val value: Map<QueryId, List<VerifiablePresentation>>) {
    init {
        require(value.isNotEmpty())
        require(value.values.all { it.isNotEmpty() })
    }
}

sealed interface WalletResponse {

    data class VpToken(
        val verifiablePresentations: VerifiablePresentations,
    ) : WalletResponse

    data class Error(val value: String, val description: String?) : WalletResponse
}

@JvmInline
value class ResponseCode(val value: String)

sealed interface GetWalletResponseMethod {
    data object Poll : GetWalletResponseMethod
    data class Redirect(val redirectUriTemplate: String) : GetWalletResponseMethod
}

/**
 * Profile, i.e. rules, that govern a Transaction.
 */
sealed interface Profile {
    /**
     * [OpenId4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
     */
    data object OpenId4VP : Profile

    /**
     * [High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
     */
    data object HAIP : Profile
}

/**
 * The entity that represents the presentation process
 */
sealed interface Presentation {
    val id: TransactionId
    val initiatedAt: Instant

    /**
     * A presentation process that has been just requested
     */
    class Requested(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        val query: DCQL,
        val transactionData: NonEmptyList<TransactionData>?,
        val requestId: RequestId,
        val requestUriMethod: RequestUriMethod,
        val nonce: Nonce,
        val responseMode: ResponseMode,
        val getWalletResponseMethod: GetWalletResponseMethod,
        val issuerChain: NonEmptyList<X509Certificate>?,
        val profile: Profile,
    ) : Presentation

    /**
     * A presentation process for which the wallet has obtained the request object.
     * Depending on the configuration of the verifier, this can be done
     * as part of the initialization of the process (when using request JAR parameter)
     * or later on (when using request_uri JAR parameter)
     */
    class RequestObjectRetrieved private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        val query: DCQL,
        val transactionData: NonEmptyList<TransactionData>?,
        val requestId: RequestId,
        val requestObjectRetrievedAt: Instant,
        val nonce: Nonce,
        val responseMode: ResponseMode,
        val getWalletResponseMethod: GetWalletResponseMethod,
        val issuerChain: NonEmptyList<X509Certificate>?,
        val profile: Profile,
    ) : Presentation {
        init {
            require(initiatedAt <= requestObjectRetrievedAt)
        }

        companion object {
            fun requestObjectRetrieved(requested: Requested, at: Instant): Either<Throwable, RequestObjectRetrieved> =
                Either.catch {
                    RequestObjectRetrieved(
                        requested.id,
                        requested.initiatedAt,
                        requested.query,
                        requested.transactionData,
                        requested.requestId,
                        at,
                        requested.nonce,
                        requested.responseMode,
                        requested.getWalletResponseMethod,
                        requested.issuerChain,
                        requested.profile,
                    )
                }
        }
    }

    /**
     * A presentation process that has been just submitted by the wallet to the verifier backend
     */
    class Submitted private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        val requestId: RequestId,
        var requestObjectRetrievedAt: Instant,
        var submittedAt: Instant,
        val walletResponse: WalletResponse,
        val nonce: Nonce,
        val responseCode: ResponseCode?,
    ) : Presentation {
        companion object {
            fun submitted(
                requestObjectRetrieved: RequestObjectRetrieved,
                at: Instant,
                walletResponse: WalletResponse,
                responseCode: ResponseCode?,
            ): Either<Throwable, Submitted> = Either.catch {
                with(requestObjectRetrieved) {
                    Submitted(
                        id,
                        initiatedAt,
                        requestId,
                        requestObjectRetrievedAt,
                        at,
                        walletResponse,
                        nonce,
                        responseCode,
                    )
                }
            }
        }
    }

    class TimedOut private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        val requestObjectRetrievedAt: Instant? = null,
        val submittedAt: Instant? = null,
        val timedOutAt: Instant,
    ) : Presentation {
        companion object {
            fun timeOut(presentation: Requested, at: Instant): Either<Throwable, TimedOut> = Either.catch {
                require(presentation.initiatedAt < at)
                TimedOut(presentation.id, presentation.initiatedAt, null, null, at)
            }

            fun timeOut(presentation: RequestObjectRetrieved, at: Instant): Either<Throwable, TimedOut> = Either.catch {
                require(presentation.initiatedAt < at)
                TimedOut(
                    presentation.id,
                    presentation.initiatedAt,
                    presentation.requestObjectRetrievedAt,
                    null,
                    at,
                )
            }

            fun timeOut(presentation: Submitted, at: Instant): Either<Throwable, TimedOut> = Either.catch {
                require(presentation.initiatedAt < at)
                TimedOut(
                    presentation.id,
                    presentation.initiatedAt,
                    presentation.requestObjectRetrievedAt,
                    presentation.submittedAt,
                    at,
                )
            }
        }
    }
}

fun Presentation.isExpired(at: Instant): Boolean {
    fun Instant.isBeforeOrEqual(at: Instant) = this <= at
    return when (this) {
        is Presentation.Requested -> initiatedAt.isBeforeOrEqual(at)
        is Presentation.RequestObjectRetrieved -> requestObjectRetrievedAt.isBeforeOrEqual(at)
        is Presentation.TimedOut -> false
        is Presentation.Submitted -> initiatedAt.isBeforeOrEqual(at)
    }
}

fun Presentation.Requested.retrieveRequestObject(clock: Clock): Either<Throwable, Presentation.RequestObjectRetrieved> =
    Presentation.RequestObjectRetrieved.requestObjectRetrieved(this, clock.now())

fun Presentation.Requested.timedOut(clock: Clock): Either<Throwable, Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.now())

fun Presentation.RequestObjectRetrieved.timedOut(clock: Clock): Either<Throwable, Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.now())

fun Presentation.RequestObjectRetrieved.submit(
    clock: Clock,
    walletResponse: WalletResponse,
    responseCode: ResponseCode?,
): Either<Throwable, Presentation.Submitted> =
    Presentation.Submitted.submitted(this, clock.now(), walletResponse, responseCode)

fun Presentation.Submitted.timedOut(clock: Clock): Either<Throwable, Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.now())
