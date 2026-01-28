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

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer

private val objectMapper: ObjectMapper by lazy { jacksonObjectMapper() }

/**
 * Converts a KotlinX Serialization serializable object to a Jackson JSON representation.
 */
internal inline fun <reified T> T.toJackson(serializer: KSerializer<T> = serializer()): Any {
    val serialized = jsonSupport.encodeToString(serializer, this)
    return objectMapper.readValue<Any>(serialized)
}
