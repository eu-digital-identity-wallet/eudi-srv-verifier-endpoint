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
@file:UseSerializers(URLStringSerializer::class, NonEmptyListSerializer::class)

package eu.europa.ec.eudi.verifier.endpoint.domain

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.serialization.NonEmptyListSerializer
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encode
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import java.net.URL
import kotlin.contracts.contract

typealias Base64UrlSafe = String

/**
 * Wrapper for a JsonObject that contains Transaction Data.
 */
@JvmInline
value class TransactionData private constructor(val value: JsonObject) {

    val type: String
        get() = value[OpenId4VPSpec.TRANSACTION_DATA_TYPE]!!.jsonPrimitive.content

    val credentialIds: NonEmptyList<String>
        get() = value[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS]!!
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

        private fun validate(value: JsonObject): Either<Throwable, TransactionData> = Either.catch {
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
            val value = buildJsonObject {
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
        ): Either<Throwable, TransactionData> = Either.catch {
            val transactionData = validate(unvalidated).getOrThrow()
            require(validCredentialIds.containsAll(transactionData.credentialIds)) {
                "invalid '${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}'"
            }
            transactionData
        }

        fun fromBase64Url(
            base64Url: String,
        ): Either<Throwable, TransactionData> = Either.catch {
            val decoded = base64UrlNoPadding.decodeToByteString(base64Url)
            val serialized = decoded.decodeToString()
            val json = jsonSupport.decodeFromString<JsonObject>(serialized)
            validate(json).getOrThrow()
        }
    }
}

internal interface SdJwtVcTransactionDataExtensions {
    val hashAlgorithms: NonEmptyList<String>?

    val hashAlgorithmsOrDefault: NonEmptyList<String>
        get() = hashAlgorithms ?: nonEmptyListOf(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHM_DEFAULT)
}

/**
 * Checks if this [JsonElement] is a [JsonPrimitive] that is a non-empty string.
 */
private fun JsonElement?.isNonEmptyString(): Boolean {
    contract {
        returns(true) implies(this@isNonEmptyString is JsonPrimitive)
    }

    return this is JsonPrimitive && this.isString && this.content.isNotEmpty()
}

/**
 * Checks if this [JsonElement] is a non-empty [JsonArray].
 */
private fun JsonElement?.isNonEmptyArray(): Boolean {
    contract {
        returns(true) implies(this@isNonEmptyArray is JsonArray)
    }

    return this is JsonArray && this.isNotEmpty()
}

/**
 * Identifier of the Signature to be created.
 */
@Serializable
@JvmInline
internal value class SignatureQualifier(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value

    companion object {
        val EuEidasQes: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_EU_EIDAS_QES)

        val EuEidasAes: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_EU_EIDAS_AES)

        val EuEidasAesQc: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_EU_EIDAS_AES_QC)

        val EuEidasQeSeal: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_EU_EIDAS_QE_SEAL)

        val EuEidasAeSeal: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_EU_EIDAS_AE_SEAL)

        val EuEidasAeSealQc: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_EU_EIDAS_AE_SEAL_QC)

        val ZaEctaAes: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_ZA_ECTA_AES)

        val ZaEctaOes: SignatureQualifier
            get() = SignatureQualifier(RQES.SIGNATURE_QUALIFIER_ZA_ECTA_OES)
    }
}

/**
 * Unique identifier for a Credential.
 */
@Serializable
@JvmInline
internal value class CredentialId(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * A label.
 */
@Serializable
@JvmInline
internal value class Label(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * OID Hash Algorithm.
 */
@Serializable
@JvmInline
internal value class HashAlgorithmOID(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * [KSerializer] for [URL]. Serializes its value as a string using [URL.toExternalForm].
 */
internal object URLStringSerializer : KSerializer<URL> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("URLString", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: URL) {
        encoder.encodeString(value.toExternalForm())
    }

    override fun deserialize(decoder: Decoder): URL = URL(decoder.decodeString())
}

/**
 * Access mode.
 */
@Serializable
@JvmInline
internal value class AccessMode(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value

    companion object {
        val Public: AccessMode
            get() = AccessMode(RQES.ACCESS_MODE_PUBLIC)

        val OneTimePassword: AccessMode
            get() = AccessMode(RQES.ACCESS_MODE_OTP)

        val BasicAuthentication: AccessMode
            get() = AccessMode(RQES.ACCESS_MODE_BASIC_AUTHENTICATION)

        val DigestAuthentication: AccessMode
            get() = AccessMode(RQES.ACCESS_MODE_DIGEST_AUTHENTICATION)

        val OAuth20: AccessMode
            get() = AccessMode(RQES.ACCESS_MODE_OAUTH20)
    }
}

/**
 * A single use password.
 */
@Serializable
@JvmInline
internal value class OneTimePassword(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * Access method for a document to be signed.
 */
@Serializable
internal data class DocumentAccessMethod(

    @SerialName(RQES.DOCUMENT_ACCESS_METHOD_ACCESS_MODE)
    @Required
    val accessMode: AccessMode,

    @SerialName(RQES.DOCUMENT_ACCESS_METHOD_OTP)
    val oneTimePassword: OneTimePassword? = null,

) {
    init {
        if (AccessMode.OneTimePassword == accessMode) {
            requireNotNull(oneTimePassword) {
                "'${RQES.DOCUMENT_ACCESS_METHOD_OTP}' is required when " +
                    "'${RQES.DOCUMENT_ACCESS_METHOD_ACCESS_MODE}' is " +
                    "'${RQES.ACCESS_MODE_OTP}'."
            }
        }
    }
}

/**
 * Data of a document to be signed.
 */
@Serializable
internal data class DocumentDigest(

    @SerialName(RQES.DOCUMENT_DIGEST_LABEL)
    @Required
    val label: Label,

    @SerialName(RQES.DOCUMENT_DIGEST_HASH)
    val hash: String? = null,

    @SerialName(RQES.DOCUMENT_DIGEST_HASH_ALGORITHM)
    val hashAlgorithm: HashAlgorithmOID? = null,

    @SerialName(RQES.DOCUMENT_DIGEST_DOCUMENT_LOCATION_URI)
    val documentLocation: URL? = null,

    @SerialName(RQES.DOCUMENT_DIGEST_DOCUMENT_LOCATION_METHOD)
    val documentAccessMethod: DocumentAccessMethod? = null,

    @SerialName(RQES.DOCUMENT_DIGEST_DATA_TO_BE_SIGNED_REPRESENTATION)
    val dataToBeSignedRepresentation: String? = null,

    @SerialName(RQES.DOCUMENT_DIGEST_DATA_TO_BE_SIGNED_REPRESENTATION_HASH_ALGORITHM)
    val dataToBeSignedRepresentationHashAlgorithm: HashAlgorithmOID? = null,

) {
    init {
        require((null == hash && null == hashAlgorithm) || (null != hash && null != hashAlgorithm)) {
            "either provide both '${RQES.DOCUMENT_DIGEST_HASH}' and '${RQES.DOCUMENT_DIGEST_HASH_ALGORITHM}', or none."
        }
        require(
            (null == dataToBeSignedRepresentation && null == dataToBeSignedRepresentationHashAlgorithm) ||
                (null != dataToBeSignedRepresentation && null != dataToBeSignedRepresentationHashAlgorithm),
        ) {
            "either provide both '${RQES.DOCUMENT_DIGEST_DATA_TO_BE_SIGNED_REPRESENTATION}' and " +
                "'${RQES.DOCUMENT_DIGEST_DATA_TO_BE_SIGNED_REPRESENTATION_HASH_ALGORITHM}', or none."
        }
        require(
            (null == documentLocation && null == documentAccessMethod) ||
                (null != documentLocation && null != documentAccessMethod),
        ) {
            "either provide both '${RQES.DOCUMENT_DIGEST_DOCUMENT_LOCATION_URI}' and " +
                "'${RQES.DOCUMENT_DIGEST_DOCUMENT_LOCATION_METHOD}', or none."
        }
        require(null != hash || null != dataToBeSignedRepresentation) {
            "either '${RQES.DOCUMENT_DIGEST_HASH}', or '${RQES.DOCUMENT_DIGEST_DATA_TO_BE_SIGNED_REPRESENTATION}' must be present."
        }
    }
}

/**
 * Unique identifier of a signing process.
 */
@Serializable
@JvmInline
internal value class ProcessId(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * Transaction Data for Qualified Electronic Signature (QES) Authorization.
 */
@Serializable
internal data class QesAuthorization(
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    @Required
    val type: String,

    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    @Required
    val credentialIds: NonEmptyList<String>,

    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)
    override val hashAlgorithms: NonEmptyList<String>? = null,

    @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER)
    val signatureQualifier: SignatureQualifier? = null,

    @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_CREDENTIAL_ID)
    val credentialId: CredentialId? = null,

    @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_DOCUMENT_DIGESTS)
    @Required
    val documentDigests: NonEmptyList<DocumentDigest>,

    @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_PROCESS_ID)
    val processId: ProcessId? = null,

) : SdJwtVcTransactionDataExtensions {
    init {
        require(TYPE == type) { "Expected '${OpenId4VPSpec.TRANSACTION_DATA_TYPE}' to be '$TYPE'. Was: '$type'." }
        require(null != credentialId || null != signatureQualifier) {
            "either '${RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_CREDENTIAL_ID}', " +
                "or '${RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER}' must be present."
        }
    }

    companion object {
        const val TYPE = RQES.TYPE_QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION
    }
}

/**
 * Transaction Data for Qualified Certification Creation Acceptance.
 */
@Serializable
internal data class QCertCreationAcceptance(
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    @Required
    val type: String,

    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    @Required
    val credentialIds: NonEmptyList<String>,

    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)
    override val hashAlgorithms: NonEmptyList<String>? = null,

    @SerialName(RQES.QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_TERM_AND_CONDITIONS_URI)
    @Required
    val termsAndConditions: URL,

    @SerialName(RQES.QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_HASH)
    @Required
    val documentHash: String,

    @SerialName(RQES.QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE_HASH_ALGORITHM)
    @Required
    val hashAlgorithm: HashAlgorithmOID,

) : SdJwtVcTransactionDataExtensions {
    init {
        require(TYPE == type) { "Expected '${OpenId4VPSpec.TRANSACTION_DATA_TYPE}' to be '$TYPE'. Was: '$type'." }
    }

    companion object {
        const val TYPE = RQES.TYPE_QUALIFIED_CERTIFICATE_CREATION_ACCEPTANCE
    }
}
