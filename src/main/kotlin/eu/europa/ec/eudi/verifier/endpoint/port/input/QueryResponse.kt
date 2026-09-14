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

sealed interface QueryResponse<out T : Any> {
    data object NotFound : QueryResponse<Nothing>

    /**
     * The presentation exists, but the query cannot be satisfied.
     *
     * [error] tells apart the reasons, which a caller must handle differently:
     * some are transient and some are terminal.
     */
    data class InvalidState(
        val error: InvalidStateError,
    ) : QueryResponse<Nothing>

    data class Found<T : Any>(
        val value: T,
    ) : QueryResponse<T>
}

/**
 * The reasons a query can be answered with [QueryResponse.InvalidState].
 */
sealed interface InvalidStateError {
    /**
     * The wallet has not submitted a response yet.
     *
     * Transient: the caller may retry the same query later.
     */
    data object PresentationNotSubmitted : InvalidStateError

    /**
     * The `response_code` provided by the caller does not match the one issued for this presentation.
     *
     * Terminal: retrying with the same `response_code` cannot succeed.
     */
    data object InvalidResponseCode : InvalidStateError
}
