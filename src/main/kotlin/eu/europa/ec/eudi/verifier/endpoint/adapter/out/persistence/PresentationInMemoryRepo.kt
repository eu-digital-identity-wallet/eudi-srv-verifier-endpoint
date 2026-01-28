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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.domain.isExpired
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.*
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap

data class PresentationStoredEntry(
    val presentation: Presentation,
    val events: NonEmptyList<PresentationEvent>?,
)

/**
 * An input-memory repository for storing [presentations][Presentation]
 */
class PresentationInMemoryRepo(
    private val presentations: ConcurrentHashMap<TransactionId, PresentationStoredEntry> = ConcurrentHashMap(),
) {

    val loadPresentationById: LoadPresentationById by lazy {
        LoadPresentationById { presentationId -> presentations[presentationId]?.presentation }
    }

    val loadPresentationByRequestId: LoadPresentationByRequestId by lazy {
        fun requestId(p: Presentation) = when (p) {
            is Presentation.Requested -> p.requestId
            is Presentation.RequestObjectRetrieved -> p.requestId
            is Presentation.Submitted -> p.requestId
            is Presentation.TimedOut -> null
        }
        LoadPresentationByRequestId { requestId ->
            presentations.values.map { it.presentation }.firstOrNull {
                requestId(it) == requestId
            }
        }
    }

    val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan by lazy {
        LoadIncompletePresentationsOlderThan { at ->
            presentations.values.map { it.presentation }.toList().filter { it.isExpired(at) }
        }
    }

    val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation ->
            val existing = presentations[presentation.id]
            presentations[presentation.id] =
                existing?.copy(presentation = presentation) ?: PresentationStoredEntry(presentation, null)
        }
    }

    val loadPresentationEvents: LoadPresentationEvents by lazy {
        LoadPresentationEvents { transactionId ->
            val p = presentations[transactionId]
            if (p == null) null
            else {
                checkNotNull(p.events)
            }
        }
    }

    val publishPresentationEvent: PublishPresentationEvent by lazy {
        PublishPresentationEvent { event ->
            log(event)
            val transactionId = event.transactionId
            val presentationAndEvent = checkNotNull(presentations[transactionId]) {
                "Cannot publish event without a presentation"
            }
            val presentationEvents = when (val existingEvents = presentationAndEvent.events) {
                null -> nonEmptyListOf(event)
                else -> existingEvents + event
            }
            presentations[transactionId] = presentationAndEvent.copy(events = presentationEvents)
        }
    }

    val deletePresentationsInitiatedBefore: DeletePresentationsInitiatedBefore by lazy {
        DeletePresentationsInitiatedBefore { at ->
            presentations.filter { (_, presentationAndEvents) -> presentationAndEvents.presentation.initiatedAt < at }
                .keys
                .onEach { presentations.remove(it) }
                .toList()
        }
    }
}

private val logger = LoggerFactory.getLogger("EVENTS")
private fun log(e: PresentationEvent) {
    fun txt(s: String) = "$s - tx: ${e.transactionId.value}"
    fun warn(s: String) = logger.warn(txt(s))
    fun info(s: String) = logger.info(txt(s))
    when (e) {
        is PresentationEvent.VerifierFailedToGetWalletResponse -> warn("Verifier failed to retrieve wallet response. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrievePresentationDefinition -> warn(
            "Wallet failed to retrieve presentation definition. Cause ${e.cause}",
        )
        is PresentationEvent.WalletFailedToPostResponse -> warn("Wallet failed to post response. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrieveRequestObject -> warn("Wallet failed to retrieve request object. Cause ${e.cause}")
        is PresentationEvent.PresentationExpired -> info("Presentation expired")
        is PresentationEvent.RequestObjectRetrieved -> info("Wallet retrieved Request Object")
        is PresentationEvent.TransactionInitialized -> info("Verifier initialized transaction")
        is PresentationEvent.VerifierGotWalletResponse -> info("Verifier retrieved wallet response")
        is PresentationEvent.WalletResponsePosted -> info("Wallet posted response")
        is PresentationEvent.AttestationStatusCheckSuccessful -> info("Attestation status check successful")
        is PresentationEvent.AttestationStatusCheckFailed -> warn("Attestation status check failed")
    }
}
