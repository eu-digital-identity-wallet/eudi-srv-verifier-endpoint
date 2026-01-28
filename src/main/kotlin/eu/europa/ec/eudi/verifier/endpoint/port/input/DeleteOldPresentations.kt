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
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.DeletePresentationsInitiatedBefore
import kotlin.time.Duration

fun interface DeleteOldPresentations {

    /**
     * Deletes old Presentations from the system.
     */
    suspend operator fun invoke(): List<TransactionId>
}

internal class DeleteOldPresentationsLive(
    private val clock: Clock,
    private val maxAge: Duration,
    private val deletePresentationsInitiatedBefore: DeletePresentationsInitiatedBefore,
) : DeleteOldPresentations {

    override suspend fun invoke(): List<TransactionId> = deletePresentationsInitiatedBefore(clock.now() - maxAge)
}
