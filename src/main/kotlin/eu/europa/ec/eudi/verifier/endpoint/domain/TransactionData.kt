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
import arrow.core.serialization.NonEmptyListSerializer
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.SignedEnvelopeProperty.Companion.ALLOWED_SIGNED_ENVELOPE_PROPERTIES
import eu.europa.ec.eudi.verifier.endpoint.domain.SignedEnvelopeProperty.Companion.DEFAULT_SIGNED_ENVELOPE_PROPERTIES
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encode
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL
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

/**
 * Identifier of the Signature to be created.
 */
@Serializable
@JvmInline
internal value class SignatureQualifier(
    val value: String,
) {
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
internal value class CredentialId(
    val value: String,
) {
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
internal value class Label(
    val value: String,
) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * Indication of the type of hash
 */
@Serializable
@JvmInline
internal value class HashType(
    val value: String,
) {
    init {
        require(value in ALLOWED_VALUES) {
            "hashType shall be either '$SDR', '$DTBSR', or '$SODR'. Was: '$value'."
        }
    }

    override fun toString(): String = value

    companion object {
        const val SDR: String = "sdr"
        const val DTBSR: String = "dtbsr"
        const val SODR: String = "sodr"

        val Default: HashType
            get() = HashType(DTBSR)

        private val ALLOWED_VALUES = setOf(SDR, DTBSR, SODR)
    }
}

/**
 * Access mode.
 */
@Serializable
@JvmInline
internal value class AccessMode(
    val value: String,
) {
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
internal value class OneTimePassword(
    val value: String,
) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * Access method for a document to be signed.
 */
@Serializable
internal data class AccessControlMethod(
    @SerialName(RQES.ACCESS_CONTROL_METHOD_TYPE)
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
 * Data of a document to be signed as per
 * [TS 119 432 v1.3.1](https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.03.01_60/ts_119432v010301p.pdf).
 */
@Serializable
internal data class DocumentDigest(
    @SerialName(RQES.DOCUMENT_DIGEST_LABEL)
    val label: Label? = null,
    @SerialName(RQES.DOCUMENT_DIGEST_HASH)
    @Required
    val hash: String,
    @SerialName(RQES.DOCUMENT_DIGEST_HASH_TYPE)
    val hashType: HashType? = HashType.Default,
    @SerialName(RQES.DOCUMENT_DIGEST_SIGNED_PROPERTIES)
    val signedProperties: NonEmptyList<Attribute>? = null,
    @SerialName(RQES.DOCUMENT_DIGEST_CIRCUMSTANTIAL_DATA)
    val circumstantialData: String? = null,
    @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_HREF)
    @Required
    val href: StringUri,
    @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_CHECKSUM)
    val checksum: Hash? = null,
    @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_ACCESS)
    val access: AccessControlMethod? = null,
)

@Serializable
data class Attribute(
    @SerialName(RQES.ATTRIBUTE_ATTRIBUTE_NAME)
    @Required
    val attributeName: String,
    @SerialName(RQES.ATTRIBUTE_ATTRIBUTE_VALUE)
    val attributeValue: String? = null,
) {
    init {
        require(attributeName.isNotBlank()) { "Attribute name must not be blank" }
    }
}

/**
 * Transaction Data for Qualified Electronic Signature (QES) Approval.
 */
@Serializable
internal data class QesApproval(
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    @Required
    val type: Type,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    @Required
    val credentialIds: NonEmptyList<CredentialID>,
    @SerialName(RFC9396.LOCATIONS)
    val locations: NonEmptyList<Location>? = null,
    @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_CREDENTIAL_ID)
    val credentialId: CredentialId? = null,
    @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER)
    val signatureQualifier: SignatureQualifier? = null,
    @SerialName(RQES.SIGNATURE_CREATION_APPROVAL_NUMBER_OF_SIGNATURES)
    @Required
    val numSignatures: UInt,
    @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_DOCUMENT_DIGESTS)
    @Required
    val documentDigests: NonEmptyList<DocumentDigest>,
    @SerialName(RQES.SIGNATURE_CREATION_APPROVAL_HASH_ALGORITHM_OID)
    @Required
    val hashAlgorithm: HashAlgorithmOID,
) {
    init {
        require(numSignatures > 0u) {
            "'numSignatures' must be positive."
        }
        require(null != credentialId || null != signatureQualifier) {
            "either '${RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_CREDENTIAL_ID}', " +
                "or '${RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER}' must be present."
        }
        require(type.value.isNotEmpty())
        require(TYPE == type.value) { "Expected '${OpenId4VPSpec.TRANSACTION_DATA_TYPE}' to be '$TYPE'. Was: '${type.value}'." }
    }

    companion object {
        const val TYPE = RQES.TYPE_QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION
    }
}

@Serializable(with = SignatureRequestSerializer::class)
internal sealed interface SignatureRequest {
    val label: Label?
    val signatureQualifier: SignatureQualifier
    val responseURI: StringUri?
    val signatureFormat: SignatureFormat?
    val conformanceLevel: ConformanceLevel?
    val signedEnvelopeProperty: SignedEnvelopeProperty?
    val signedProperties: NonEmptyList<Attribute>?
    val referenceUri: ReferenceUri?
    val circumstantialData: String?
    val signAlgo: String
    val signAlgoParams: String?

    @Serializable
    data class SignatureRequestWithDocumentData(
        @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER)
        @Required
        override val signatureQualifier: SignatureQualifier,
        @SerialName(RQES.SIGNATURE_REQUEST_RESPONSE_URI)
        override val responseURI: StringUri? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_FORMAT)
        override val signatureFormat: SignatureFormat? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_CONFORMANCE_LEVEL)
        override val conformanceLevel: ConformanceLevel? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY)
        override val signedEnvelopeProperty: SignedEnvelopeProperty? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_PROPERTIES)
        override val signedProperties: NonEmptyList<Attribute>? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_REFERENCE_URI)
        override val referenceUri: ReferenceUri? = null,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_DATA_LABEL)
        override val label: Label? = null,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_DATA_DOCUMENT)
        @Required
        val document: String,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_DATA_DOCUMENT_TYPE)
        val documentType: DocumentType = DocumentType.DEFAULT,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_DATA_CIRCUMSTANTIAL_DATA)
        override val circumstantialData: String? = null,
        @SerialName(RQES.SIGNING_ALGORITHM_SIGN_ALGO)
        @Required
        override val signAlgo: String,
        @SerialName(RQES.SIGNING_ALGORITHM_SIGN_ALGO_PARAMS)
        override val signAlgoParams: String? = null,
    ) : SignatureRequest {
        init {
            validateSignatureRequest(
                signatureFormat = signatureFormat,
                signedEnvelopeProperty = signedEnvelopeProperty,
                referenceUri = referenceUri,
            )
        }
    }

    @Serializable
    data class SignatureRequestWithDocumentReference(
        @SerialName(RQES.QUALIFIED_ELECTRONIC_SIGNATURE_AUTHORIZATION_SIGNATURE_QUALIFIER)
        @Required
        override val signatureQualifier: SignatureQualifier,
        @SerialName(RQES.SIGNATURE_REQUEST_RESPONSE_URI)
        override val responseURI: StringUri? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_FORMAT)
        override val signatureFormat: SignatureFormat? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_CONFORMANCE_LEVEL)
        override val conformanceLevel: ConformanceLevel? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY)
        override val signedEnvelopeProperty: SignedEnvelopeProperty? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_PROPERTIES)
        override val signedProperties: NonEmptyList<Attribute>? = null,
        @SerialName(RQES.ADES_PARAMETERS_SIGNATURE_REFERENCE_URI)
        override val referenceUri: ReferenceUri? = null,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_LABEL)
        override val label: Label? = null,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_ACCESS)
        val access: AccessControlMethod? = null,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_HREF)
        @Required
        val href: StringUri,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_CHECKSUM)
        val checksum: Hash? = null,
        @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_CIRCUMSTANTIAL_DATA)
        override val circumstantialData: String? = null,
        @SerialName(RQES.SIGNING_ALGORITHM_SIGN_ALGO)
        @Required
        override val signAlgo: String,
        @SerialName(RQES.SIGNING_ALGORITHM_SIGN_ALGO_PARAMS)
        override val signAlgoParams: String? = null,
    ) : SignatureRequest {
        init {
            validateSignatureRequest(
                signatureFormat = signatureFormat,
                signedEnvelopeProperty = signedEnvelopeProperty,
                referenceUri = referenceUri,
            )
        }
    }

    companion object {
        private fun validateSignatureRequest(
            signatureFormat: SignatureFormat?,
            signedEnvelopeProperty: SignedEnvelopeProperty?,
            referenceUri: ReferenceUri?,
        ) {
            val selectedSignatureFormat = signatureFormat?.value ?: SignatureFormat.CADES
            val selectedSignedEnvelopeProperty =
                signedEnvelopeProperty?.value ?: DEFAULT_SIGNED_ENVELOPE_PROPERTIES.getValue(selectedSignatureFormat)

            require(selectedSignedEnvelopeProperty in ALLOWED_SIGNED_ENVELOPE_PROPERTIES.getValue(selectedSignatureFormat)) {
                "'signed_envelope_property' is not valid for 'signature_format' '$selectedSignatureFormat'. " +
                    "Was: '$selectedSignedEnvelopeProperty'."
            }

            if (referenceUri != null) {
                require(
                    when (selectedSignatureFormat) {
                        SignatureFormat.XADES,
                        SignatureFormat.JADES,
                        -> {
                            selectedSignedEnvelopeProperty ==
                                RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_DETACHED
                        }

                        else -> {
                            false
                        }
                    },
                ) {
                    "'referenceUri' is only applicable when 'signature_format' is '${SignatureFormat.XADES}' " +
                        "or '${SignatureFormat.JADES}' and 'signed_envelope_property' is " +
                        "'${RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_DETACHED}'."
                }
            }
        }
    }
}

/**
 * Transaction Data for Qualified Electronic Signature (QES) Request.
 */
@Serializable
internal data class QesRequest(
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    @Required
    val type: Type,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    @Required
    val credentialIds: NonEmptyList<CredentialID>,
    @SerialName(RQES.REQUESTS_SIGNATURE_REQUESTS)
    @Required
    val signatureRequests: NonEmptyList<SignatureRequest>,
) {
    init {
        require(type.value.isNotEmpty())
        require(
            TYPE == type.value,
        ) { "Expected '${OpenId4VPSpec.TRANSACTION_DATA_TYPE}' to be '${QesApproval.TYPE}'. Was: '${type.value}'." }
    }

    companion object {
        const val TYPE = RQES.TYPE_QUALIFIED_ELECTRONIC_SIGNATURE_REQUEST
    }
}

@Serializable
@JvmInline
value class ConformanceLevel(
    val value: String,
) {
    init {
        require(value.isNotBlank()) { "ConformanceLevel must not be empty" }
        require(value in requiredConformanceLevel)
    }

    companion object {
        private val requiredConformanceLevel =
            listOf("AdES-B-B", "AdES-B-T", "AdES-B-LT", "AdES-B-LTA", "AdES-B", "AdES-T", "AdES-LT", "AdES-LTA")
    }
}

@Serializable
@JvmInline
value class DocumentType(
    val value: String,
) {
    init {
        require(value == RQES.DOCUMENTS_DOCUMENT_TYPE_SFD || value == RQES.DOCUMENTS_DOCUMENT_TYPE_SOD) {
            "'documentType' can be either '${RQES.DOCUMENTS_DOCUMENT_TYPE_SFD}' or '${RQES.DOCUMENTS_DOCUMENT_TYPE_SOD}'."
        }
    }

    companion object {
        val DEFAULT = DocumentType(RQES.DOCUMENTS_DOCUMENT_TYPE_SOD)
    }
}

@Serializable
@JvmInline
value class ReferenceUri(
    val value: StringUri,
)

@Serializable
@JvmInline
value class SignedEnvelopeProperty(
    val value: String,
) {
    companion object {
        val ALLOWED_SIGNED_ENVELOPE_PROPERTIES =
            mapOf(
                SignatureFormat.CADES to
                    setOf(
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_DETACHED,
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ATTACHED,
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_PARALLEL,
                    ),
                SignatureFormat.PADES to
                    setOf(
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_CERTIFICATION,
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_REVISION,
                    ),
                SignatureFormat.XADES to
                    setOf(
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ENVELOPED,
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ENVELOPING,
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_DETACHED,
                    ),
                SignatureFormat.JADES to
                    setOf(
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_DETACHED,
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ATTACHED,
                        RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_PARALLEL,
                    ),
            )

        val DEFAULT_SIGNED_ENVELOPE_PROPERTIES =
            mapOf(
                SignatureFormat.CADES to RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ATTACHED,
                SignatureFormat.PADES to RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_CERTIFICATION,
                SignatureFormat.XADES to RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ENVELOPED,
                SignatureFormat.JADES to RQES.ADES_PARAMETERS_SIGNATURE_SIGNED_ENVELOPE_PROPERTY_ATTACHED,
            )
    }
}

@Serializable
@JvmInline
value class SignatureFormat(
    val value: String,
) {
    init {
        require(value in ALLOWED_SIGNATURES)
    }

    companion object {
        const val CADES = "C"
        const val XADES = "X"
        const val PADES = "P"
        const val JADES = "J"

        private val ALLOWED_SIGNATURES = setOf(CADES, XADES, PADES, JADES)
    }
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

@Serializable
@JvmInline
value class Location(
    val value: StringUri,
)

@Serializable
@JvmInline
value class HashAlgorithmOID(
    val value: String,
) {
    init {
        require(value.isNotEmpty())
    }
}

@Serializable
data class Hash(
    @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_HASH_VALUE)
    @Required
    val value: String,
    @SerialName(RQES.DOCUMENTS_DOCUMENT_REFERENCE_HASH_ALGORITHM_OID)
    @Required
    val algorithmOID: HashAlgorithmOID,
)

typealias StringUri =
    @Serializable(with = UriStringSerializer::class)
    URI

object UriStringSerializer : KSerializer<URI> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("UriStringSerializer", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: URI,
    ) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): URI = URI.create(decoder.decodeString())
}

/**
 * [KSerializer] for [URL]. Serializes its value as a string using [URL.toExternalForm].
 */
internal object URLStringSerializer : KSerializer<URL> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("URLString", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: URL,
    ) {
        encoder.encodeString(value.toExternalForm())
    }

    override fun deserialize(decoder: Decoder): URL = URL(decoder.decodeString())
}

/**
 * [KSerializer] for [SignatureRequest].
 */
internal object SignatureRequestSerializer : KSerializer<SignatureRequest> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("SignatureRequest")

    override fun deserialize(decoder: Decoder): SignatureRequest {
        require(decoder is JsonDecoder) {
            "SignatureRequestSerializer supports JSON only."
        }

        val element = decoder.decodeJsonElement()
        val jsonObject = element.jsonObject

        val hasDocumentData = RQES.DOCUMENTS_DOCUMENT_DATA_DOCUMENT in jsonObject
        val hasDocumentReference = RQES.DOCUMENTS_DOCUMENT_REFERENCE_HREF in jsonObject

        require(hasDocumentData xor hasDocumentReference) {
            "Exactly one of '${RQES.DOCUMENTS_DOCUMENT_DATA_DOCUMENT}' or '${RQES.DOCUMENTS_DOCUMENT_REFERENCE_HREF}' must be present."
        }

        return if (hasDocumentData) {
            decoder.json.decodeFromJsonElement(
                SignatureRequest.SignatureRequestWithDocumentData.serializer(),
                element,
            )
        } else {
            decoder.json.decodeFromJsonElement(
                SignatureRequest.SignatureRequestWithDocumentReference.serializer(),
                element,
            )
        }
    }

    override fun serialize(
        encoder: Encoder,
        value: SignatureRequest,
    ) {
        require(encoder is JsonEncoder) {
            "SignatureRequestSerializer supports JSON only."
        }

        val element =
            when (value) {
                is SignatureRequest.SignatureRequestWithDocumentData -> {
                    encoder.json.encodeToJsonElement(
                        SignatureRequest.SignatureRequestWithDocumentData.serializer(),
                        value,
                    )
                }

                is SignatureRequest.SignatureRequestWithDocumentReference -> {
                    encoder.json.encodeToJsonElement(
                        SignatureRequest.SignatureRequestWithDocumentReference.serializer(),
                        value,
                    )
                }
            }

        encoder.encodeJsonElement(element)
    }
}
