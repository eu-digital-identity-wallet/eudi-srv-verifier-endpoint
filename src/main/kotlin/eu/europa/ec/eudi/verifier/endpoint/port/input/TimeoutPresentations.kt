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

import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.domain.timedOut
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import kotlin.time.Duration

fun interface TimeoutPresentations {

    suspend operator fun invoke(): List<TransactionId>
}

class TimeoutPresentationsLive(
    private val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan,
    private val storePresentation: StorePresentation,
    private val maxAge: Duration,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) : TimeoutPresentations {
    override suspend operator fun invoke(): List<TransactionId> {
        val expireBefore = clock.now() - maxAge
        return loadIncompletePresentationsOlderThan(expireBefore).mapNotNull { timeout(it)?.id }
    }

    private suspend fun timeout(presentation: Presentation): Presentation? {
        val timeout = when (presentation) {
            is Presentation.Requested -> presentation.timedOut(clock).getOrNull()
            is Presentation.RequestObjectRetrieved -> presentation.timedOut(clock).getOrNull()
            is Presentation.Submitted -> presentation.timedOut(clock).getOrNull()
            is Presentation.TimedOut -> null
        }
        return timeout?.also { timedOut ->
            logExpired(timedOut)
            storePresentation(timedOut)
        }
    }

    private suspend fun logExpired(presentation: Presentation.TimedOut) {
        val event = PresentationEvent.PresentationExpired(presentation.id, presentation.timedOutAt)
        publishPresentationEvent(event)
    }
}
