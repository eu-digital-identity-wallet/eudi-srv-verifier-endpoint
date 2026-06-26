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

import arrow.core.NonEmptyList
import arrow.core.raise.context.Raise
import arrow.core.raise.context.ensure
import com.eygraber.uri.Url
import kotlinx.serialization.json.JsonObject
import java.security.cert.X509Certificate
import kotlin.time.Instant

@JvmInline
value class TransactionId(
    val value: String,
) {
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
value class RequestId(
    val value: String,
) {
    init {
        require(value.isNotBlank())
    }

    override fun toString(): String = value
}

@JvmInline
value class Nonce(
    val value: String,
) {
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

    data class Str(
        val value: String,
        override val format: Format,
    ) : VerifiablePresentation {
        init {
            require(value.isNotBlank()) { "VpToken cannot be blank" }
        }
    }

    data class Json(
        val value: JsonObject,
        override val format: Format,
    ) : VerifiablePresentation {
        init {
            require(value.isNotEmpty()) { "VpToken must contain claims" }
        }
    }
}

/**
 * The Wallet's response to a 'vp_token' request.
 */
@JvmInline
value class VerifiablePresentations(
    val value: Map<QueryId, List<VerifiablePresentation>>,
) {
    init {
        require(value.isNotEmpty())
        require(value.values.all { it.isNotEmpty() })
    }
}

sealed interface WalletResponse {
    data class VpToken(
        val verifiablePresentations: VerifiablePresentations,
    ) : WalletResponse

    data class Error(
        val value: String,
        val description: String?,
    ) : WalletResponse
}

@JvmInline
value class ResponseCode(
    val value: String,
)

sealed interface GetWalletResponseMethod {
    data object Poll : GetWalletResponseMethod

    data class Redirect(
        val redirectUriTemplate: String,
    ) : GetWalletResponseMethod
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

    /**
     * [ETSI119472Part2 Profile](https://cdn.standards.iteh.ai/samples/etsi/etsi-ts-119-472-2-v1-2-1-2026-03-/779cc7937e774583a475b9b2381c65bf/etsi-ts-119-472-2-v1-2-1-2026-03-.pdf)
     */
    data object ETSI119472Part2 : Profile
}

sealed interface Channel {
    val responseMode: ResponseMode

    data class OverHttp(
        override val responseMode: ResponseMode.OverHttp,
        val requestUriMethod: RequestUriMethod,
        val getWalletResponseMethod: GetWalletResponseMethod,
        val requestId: RequestId,
    ) : Channel

    data class OverDcApi(
        override val responseMode: ResponseMode.OverDcApi,
        val origin: Url,
    ) : Channel
}

/**
 * The entity that represents the presentation process
 */
sealed interface Presentation {
    val id: TransactionId
    val initiatedAt: Instant
    val channel: Channel

    /**
     * A presentation process that has been just requested
     */
    class Requested(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val channel: Channel.OverHttp,
        val query: DCQL,
        val transactionData: NonEmptyList<TransactionData>?,
        val nonce: Nonce,
        val issuerChain: NonEmptyList<X509Certificate>?,
        val profile: Profile,
    ) : Presentation

    /**
     * A presentation process for which the wallet has obtained the request object.
     * Depending on the configuration of the verifier, this can be done
     * as part of the initialization of the process (when using request JAR parameter)
     * or later on (when using request_uri JAR parameter)
     */
    class RequestObjectRetrieved(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val channel: Channel,
        val query: DCQL,
        val transactionData: NonEmptyList<TransactionData>?,
        val requestObjectRetrievedAt: Instant,
        val nonce: Nonce,
        val issuerChain: NonEmptyList<X509Certificate>?,
        val profile: Profile,
    ) : Presentation {
        init {
            require(initiatedAt <= requestObjectRetrievedAt)
        }

        companion object {
            fun requestObjectRetrieved(
                requested: Requested,
                at: Instant,
            ): RequestObjectRetrieved =
                RequestObjectRetrieved(
                    requested.id,
                    requested.initiatedAt,
                    requested.channel,
                    requested.query,
                    requested.transactionData,
                    at,
                    requested.nonce,
                    requested.issuerChain,
                    requested.profile,
                )
        }
    }

    /**
     * A presentation process that has been just submitted by the wallet to the verifier backend
     */
    class Submitted private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val channel: Channel,
        var requestObjectRetrievedAt: Instant,
        var submittedAt: Instant,
        val walletResponse: WalletResponse,
        val nonce: Nonce,
        val responseCode: ResponseCode?,
    ) : Presentation {
        companion object {
            context(_: Raise<String>)
            fun submitted(
                requestObjectRetrieved: RequestObjectRetrieved,
                at: Instant,
                walletResponse: WalletResponse,
                responseCode: ResponseCode?,
            ): Submitted =
                with(requestObjectRetrieved) {
                    Submitted(
                        id,
                        initiatedAt,
                        channel,
                        requestObjectRetrievedAt,
                        at,
                        walletResponse,
                        nonce,
                        responseCode,
                    )
                }
        }
    }

    class TimedOut private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val channel: Channel,
        val requestObjectRetrievedAt: Instant?,
        val timedOutAt: Instant,
    ) : Presentation {
        companion object {
            context(_: Raise<String>)
            fun timeOut(
                presentation: Requested,
                at: Instant,
            ): TimedOut {
                ensure(presentation.initiatedAt < at) { "Presentation ${presentation.initiatedAt} is before $at" }
                return TimedOut(presentation.id, presentation.initiatedAt, presentation.channel, null, at)
            }

            context(_: Raise<String>)
            fun timeOut(
                presentation: RequestObjectRetrieved,
                at: Instant,
            ): TimedOut {
                ensure(presentation.initiatedAt < at) { "Presentation ${presentation.initiatedAt} is before $at" }
                return TimedOut(
                    presentation.id,
                    presentation.initiatedAt,
                    presentation.channel,
                    presentation.requestObjectRetrievedAt,
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

fun Presentation.Requested.retrieveRequestObject(clock: Clock): Presentation.RequestObjectRetrieved =
    Presentation.RequestObjectRetrieved.requestObjectRetrieved(this, clock.now())

context(_: Raise<String>)
fun Presentation.Requested.timedOut(clock: Clock): Presentation.TimedOut = Presentation.TimedOut.timeOut(this, clock.now())

context(_: Raise<String>)
fun Presentation.RequestObjectRetrieved.timedOut(clock: Clock): Presentation.TimedOut = Presentation.TimedOut.timeOut(this, clock.now())

context(_: Raise<String>)
fun Presentation.RequestObjectRetrieved.submit(
    clock: Clock,
    walletResponse: WalletResponse,
    responseCode: ResponseCode?,
): Presentation.Submitted = Presentation.Submitted.submitted(this, clock.now(), walletResponse, responseCode)
