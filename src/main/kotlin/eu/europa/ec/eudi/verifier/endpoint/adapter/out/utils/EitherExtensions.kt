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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils

import arrow.core.Either
import arrow.core.getOrElse

internal fun <T> Either<Throwable, T>.getOrThrow(): T = getOrElse { throw it }

internal fun <T, E : Exception> Either<Throwable, T>.getOrThrow(convert: (Throwable) -> E): T =
    fold(
        ifLeft = { throw convert(it) },
        ifRight = { it },
    )

internal fun <T> Either<Throwable, T>.toResult(): Result<T> =
    fold(
        ifLeft = { Result.failure(it) },
        ifRight = { Result.success(it) },
    )
