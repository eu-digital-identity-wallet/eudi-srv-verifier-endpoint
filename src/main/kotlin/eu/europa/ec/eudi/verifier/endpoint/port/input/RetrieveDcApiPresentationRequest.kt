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

import eu.europa.ec.eudi.verifier.endpoint.domain.Channel
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationEvents
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent

fun interface RetrieveDcApiPresentationRequest {
    suspend operator fun invoke(transactionId: TransactionId): QueryResponse<InitDcApiTransactionResponseTO>
}

class RetrieveDcApiPresentationRequestLive(
    private val loadPresentationById: LoadPresentationById,
    private val loadPresentationEvents: LoadPresentationEvents,
) : RetrieveDcApiPresentationRequest {
    override suspend fun invoke(transactionId: TransactionId): QueryResponse<InitDcApiTransactionResponseTO> {
        val presentationById = loadPresentationById(transactionId) ?: return QueryResponse.NotFound

        if (presentationById !is Presentation.RequestObjectRetrieved) return QueryResponse.InvalidState
        require(presentationById.channel is Channel.OverDcApi)

        val events = loadPresentationEvents(transactionId)
        checkNotNull(events)

        val dcApiEvent = events.filterIsInstance<PresentationEvent.DcApiTransactionInitialized>().first()

        return QueryResponse.Found(InitDcApiTransactionResponseTO(dcApiEvent.response, transactionId.value))
    }
}
