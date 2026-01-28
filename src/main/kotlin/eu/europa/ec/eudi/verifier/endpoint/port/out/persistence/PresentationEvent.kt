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
package eu.europa.ec.eudi.verifier.endpoint.port.out.persistence

import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.ProfileTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseAcceptedTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import kotlin.time.Instant

sealed interface PresentationEvent {
    val transactionId: TransactionId
    val timestamp: Instant

    data class TransactionInitialized(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val response: InitTransactionResponse.JwtSecuredAuthorizationRequestTO,
        val profile: ProfileTO,
    ) : PresentationEvent

    data class RequestObjectRetrieved(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val jwt: Jwt,
    ) : PresentationEvent

    data class FailedToRetrieveRequestObject(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val cause: String,
    ) : PresentationEvent

    data class FailedToRetrievePresentationDefinition(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val cause: String,
    ) : PresentationEvent

    data class WalletResponsePosted(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val walletResponse: WalletResponseTO,
        val verifierEndpointResponse: WalletResponseAcceptedTO?,
    ) : PresentationEvent

    data class WalletFailedToPostResponse(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val cause: WalletResponseValidationError,
    ) : PresentationEvent

    data class VerifierGotWalletResponse(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val walletResponse: WalletResponseTO,
    ) : PresentationEvent

    data class VerifierFailedToGetWalletResponse(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val cause: String,
    ) : PresentationEvent

    data class PresentationExpired(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
    ) : PresentationEvent

    data class AttestationStatusCheckSuccessful(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val statusReference: StatusReference,
    ) : PresentationEvent

    data class AttestationStatusCheckFailed(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val statusReference: StatusReference?,
        val cause: String?,
    ) : PresentationEvent
}
