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
package eu.europa.ec.eudi.verifier.endpoint.domain

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encode
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.contracts.contract

typealias Base64UrlSafe = String

/**
 * Wrapper for a JsonObject that contains Transaction Data.
 */
@JvmInline
value class TransactionData private constructor(
    val value: JsonObject,
) {
    val type: String
        get() = value[OpenId4VPSpec.TRANSACTION_DATA_TYPE]!!.jsonPrimitive.content

    val credentialIds: NonEmptyList<String>
        get() =
            value[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS]!!
                .jsonArray
                .map { it.jsonPrimitive.content }
                .toNonEmptyListOrNull()!!

    val base64Url: Base64UrlSafe
        get() {
            val serialized = jsonSupport.encodeToString(value)
            val decoded = serialized.encodeToByteString()
            val encoded = base64UrlNoPadding.encode(decoded)
            return encoded
        }

    companion object {
        private fun validate(value: JsonObject): Either<Throwable, TransactionData> =
            Either.catch {
                val type = value[OpenId4VPSpec.TRANSACTION_DATA_TYPE]
                require(type.isNonEmptyString()) {
                    "'${OpenId4VPSpec.TRANSACTION_DATA_TYPE}' is required and must not be a non-empty string"
                }

                val credentialIds = value[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS]
                require(credentialIds.isNonEmptyArray() && credentialIds.all { it.isNonEmptyString() }) {
                    "'${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}' is required and must be a non-empty array of non-empty strings"
                }

                TransactionData(value)
            }

        operator fun invoke(
            type: String,
            credentialIds: NonEmptyList<String>,
            builder: JsonObjectBuilder.() -> Unit = {},
        ): Either<Throwable, TransactionData> {
            val value =
                buildJsonObject {
                    builder()

                    put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, type)
                    putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                        addAll(credentialIds)
                    }
                }
            return validate(value)
        }

        fun validate(
            unvalidated: JsonObject,
            validCredentialIds: List<String>,
        ): Either<Throwable, TransactionData> =
            Either.catch {
                val transactionData = validate(unvalidated).getOrThrow()
                require(validCredentialIds.containsAll(transactionData.credentialIds)) {
                    "invalid '${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}'"
                }
                transactionData
            }

        fun fromBase64Url(base64Url: String): Either<Throwable, TransactionData> =
            Either.catch {
                val decoded = base64UrlNoPadding.decodeToByteString(base64Url)
                val serialized = decoded.decodeToString()
                val json = jsonSupport.decodeFromString<JsonObject>(serialized)
                validate(json).getOrThrow()
            }
    }
}

/**
 * Checks if this [JsonElement] is a [JsonPrimitive] that is a non-empty string.
 */
private fun JsonElement?.isNonEmptyString(): Boolean {
    contract {
        returns(true) implies (this@isNonEmptyString is JsonPrimitive)
    }

    return this is JsonPrimitive && this.isString && this.content.isNotEmpty()
}

/**
 * Checks if this [JsonElement] is a non-empty [JsonArray].
 */
private fun JsonElement?.isNonEmptyArray(): Boolean {
    contract {
        returns(true) implies (this@isNonEmptyArray is JsonArray)
    }

    return this is JsonArray && this.isNotEmpty()
}

@Serializable
@JvmInline
value class Type(
    val value: String,
)

@Serializable
@JvmInline
value class CredentialID(
    val value: String,
) {
    init {
        require(value.isNotEmpty())
    }
}
