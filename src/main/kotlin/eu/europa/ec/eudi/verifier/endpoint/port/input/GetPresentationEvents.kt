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

import arrow.core.NonEmptyList
import arrow.core.max
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationEvents
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlin.time.Instant

@Serializable
data class PresentationEventsTO(
    @SerialName("transaction_id") @Required val transactionId: String,
    @SerialName("last_updated") @Required val lastUpdated: Long,
    @SerialName("events") @Required val events: List<JsonObject>,
)

fun interface GetPresentationEvents {
    suspend operator fun invoke(transactionId: TransactionId): QueryResponse<PresentationEventsTO>
}

class GetPresentationEventsLive(

    private val loadPresentationById: LoadPresentationById,
    private val loadPresentationEvents: LoadPresentationEvents,
) : GetPresentationEvents {
    override suspend fun invoke(
        transactionId: TransactionId,
    ): QueryResponse<PresentationEventsTO> = coroutineScope {
        if (presentationExists(transactionId)) {
            val events = loadPresentationEvents(transactionId)
            checkNotNull(events) { "Didn't find any events for transaction $transactionId" }
            val lastTimestamp = events.map { it.timestamp }.max()
            val transferObject = PresentationEventsTO(transactionId, lastTimestamp, events)
            QueryResponse.Found(transferObject)
        } else {
            QueryResponse.NotFound
        }
    }

    private suspend fun presentationExists(transactionId: TransactionId): Boolean =
        loadPresentationById(transactionId) != null
}

private operator fun PresentationEventsTO.Companion.invoke(
    transactionId: TransactionId,
    lastUpdated: Instant,
    events: NonEmptyList<PresentationEvent>,
) =
    PresentationEventsTO(
        transactionId = transactionId.value,
        lastUpdated = lastUpdated.toEpochMilliseconds(),
        events = events.map { event ->
            require(event.transactionId == transactionId)
            toTransferObject(event)
        }.toList(),
    )

private fun toTransferObject(event: PresentationEvent) = buildJsonObject {
    put("timestamp", event.timestamp.toEpochMilliseconds())
    putEventNameAndActor(event)
    when (event) {
        is PresentationEvent.TransactionInitialized -> {
            put("response", event.response.json())
            put("profile", event.profile.json())
        }

        is PresentationEvent.RequestObjectRetrieved -> {
            put("jwt", event.jwt)
        }

        is PresentationEvent.FailedToRetrieveRequestObject -> {
            put("cause", event.cause)
        }

        is PresentationEvent.FailedToRetrievePresentationDefinition -> {
            put("cause", event.cause)
        }

        is PresentationEvent.WalletResponsePosted -> {
            put("wallet_response", event.walletResponse.json())
        }
        is PresentationEvent.WalletFailedToPostResponse -> {
            put("cause", event.cause.asText())
        }

        is PresentationEvent.VerifierGotWalletResponse -> {
            put("wallet_response", event.walletResponse.json())
        }

        is PresentationEvent.VerifierFailedToGetWalletResponse -> {
            put("cause", event.cause)
        }

        is PresentationEvent.PresentationExpired -> {
            // No extra information to add
        }

        is PresentationEvent.AttestationStatusCheckSuccessful -> {
            put("status_reference", event.statusReference.json())
        }

        is PresentationEvent.AttestationStatusCheckFailed -> {
            put("status_reference", event.statusReference.json())
            put("cause", event.cause)
        }
    }
}

@Serializable
private enum class Actor {
    Verifier,
    Wallet,
    VerifierEndPoint,
}

private fun JsonObjectBuilder.putEventNameAndActor(e: PresentationEvent) {
    val (eventName, actor) = when (e) {
        is PresentationEvent.TransactionInitialized -> "Transaction initialized" to Actor.Verifier
        is PresentationEvent.RequestObjectRetrieved -> "Request object retrieved" to Actor.Wallet
        is PresentationEvent.FailedToRetrieveRequestObject -> "FailedToRetrieve request" to Actor.Wallet
        is PresentationEvent.FailedToRetrievePresentationDefinition -> "Failed to retrieve presentation definition" to Actor.Wallet
        is PresentationEvent.WalletResponsePosted -> "Wallet response posted" to Actor.Wallet
        is PresentationEvent.WalletFailedToPostResponse -> "Wallet failed to post response" to Actor.Wallet
        is PresentationEvent.VerifierGotWalletResponse -> "Verifier got wallet response" to Actor.Verifier
        is PresentationEvent.VerifierFailedToGetWalletResponse -> "Verifier failed to get wallet" to Actor.Verifier
        is PresentationEvent.PresentationExpired -> "Presentation expired" to Actor.VerifierEndPoint
        is PresentationEvent.AttestationStatusCheckSuccessful -> "Attestation status check succeeded" to Actor.VerifierEndPoint
        is PresentationEvent.AttestationStatusCheckFailed -> "Attestation status check failed" to Actor.VerifierEndPoint
    }
    put("event", eventName)
    put("actor", actor.json())
}

private fun WalletResponseValidationError.asText(): String =
    when (this) {
        WalletResponseValidationError.IncorrectState -> "Incorrect state"
        WalletResponseValidationError.MissingVpToken -> "Missing vp_token"
        is WalletResponseValidationError.InvalidVpToken -> "vp_token is not valid: ${message}${cause?.message?.let { ", $it"}}"
        is WalletResponseValidationError.PresentationNotFound -> "Presentation not found"
        is WalletResponseValidationError.PresentationNotInExpectedState -> "Presentation non in expected state"
        is WalletResponseValidationError.UnexpectedResponseMode -> "Unexpected response mode. Expected $expected, actual $actual"
        WalletResponseValidationError.RequiredCredentialSetNotSatisfied ->
            "vp_token does not satisfy all the required credential sets of the query"
        WalletResponseValidationError.InvalidPresentationSubmission -> "Presentation submission is not valid"
        is WalletResponseValidationError.InvalidEncryptedResponse -> "Encrypted response is not valid: '${error.message}'"
        WalletResponseValidationError.HAIPValidationError.DeviceResponseContainsMoreThanOneMDoc -> {
            "DeviceResponse contains more than one MDocs"
        }

        is WalletResponseValidationError.HAIPValidationError.UnsupportedMsoRevocationMechanism -> {
            "MSO uses unsupported revocation mechanisms. Used: '${used.joinToString()}', allowed: '${allowed.joinToString()}'"
        }

        WalletResponseValidationError.HAIPValidationError.SdJwtVcMustUseTokenStatusList -> {
            "SD-JWT VC must use Token Status List as revocation mechanism"
        }
    }

private inline fun <reified A> A.json() = Json.encodeToJsonElement(this)
