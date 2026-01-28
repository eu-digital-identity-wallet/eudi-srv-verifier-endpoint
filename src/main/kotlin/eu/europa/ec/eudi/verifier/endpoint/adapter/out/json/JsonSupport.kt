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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.json

import arrow.core.Either
import com.nimbusds.jose.util.JSONObjectUtils
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.serializer

internal val jsonSupport = Json {
    prettyPrint = false
    ignoreUnknownKeys = true
    explicitNulls = false
}

internal inline fun <reified T> JsonElement.decodeAs(deserializer: DeserializationStrategy<T> = serializer()): Either<Throwable, T> =
    Either.catch {
        jsonSupport.decodeFromJsonElement(deserializer, this)
    }

internal fun Map<String, Any?>.toJsonObject(): JsonObject {
    val jsonString = JSONObjectUtils.toJSONString(this)
    return jsonSupport.decodeFromString(jsonString)
}
