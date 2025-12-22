/*
 * Copyright (c) 2023 European Commission
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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.getOrElse
import arrow.core.raise.either
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.InvalidDocument
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509CertificateChain
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.x5cShouldBeTrustedOrNull
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDoc
import kotlinx.datetime.atStartOfDayIn
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

private val log = LoggerFactory.getLogger(ValidateMsoMdocDeviceResponse::class.java)

/**
 * Indicates the reason why DeviceResponse failed to validate.
 */
@Serializable
internal enum class ValidationFailureErrorTypeTO {
    CannotBeDecoded,
    NotOkDeviceResponseStatus,
    InvalidDocuments,
    InvalidIssuerChain,
}

/**
 * Details abouts the reason why DeviceResponse failed to validate.
 */
@Serializable
internal data class ValidationErrorTO(
    val type: ValidationFailureErrorTypeTO,
    val deviceResponseStatus: Int? = null,
    val invalidDocuments: List<InvalidDocumentTO>? = null,
) {
    companion object {
        fun cannotBeDecoded(): ValidationErrorTO =
            ValidationErrorTO(type = ValidationFailureErrorTypeTO.CannotBeDecoded)

        fun notOkDeviceResponseStatus(deviceResponseStatus: Int): ValidationErrorTO =
            ValidationErrorTO(
                type = ValidationFailureErrorTypeTO.NotOkDeviceResponseStatus,
                deviceResponseStatus = deviceResponseStatus,
            )

        fun invalidDocuments(invalidDocuments: NonEmptyList<InvalidDocumentTO>): ValidationErrorTO =
            ValidationErrorTO(
                type = ValidationFailureErrorTypeTO.InvalidDocuments,
                invalidDocuments = invalidDocuments,
            )

        fun invalidIssuerChain(): ValidationErrorTO =
            ValidationErrorTO(type = ValidationFailureErrorTypeTO.InvalidIssuerChain)
    }
}

/**
 * Indicates the reason why an MDoc document withing a DeviceResponse failed to validate.
 */
@Serializable
internal enum class DocumentErrorTO {
    MissingValidityInfo,
    ExpiredValidityInfo,
    IssuerKeyIsNotEC,
    InvalidIssuerSignature,
    X5CNotTrusted,
    DocumentTypeNotMatching,
    InvalidIssuerSignedItems,
    NoMatchingX5CValidator,
    DocumentHasBeenRevoked,
    DeviceKeyIsNotEC,
    DeviceKeyNotAuthorizedToSignItems,
    DevicePublicKeyCannotBeParsed,
    InvalidDeviceSignature,
    MissingDeviceSigned,
}

/**
 * Details about the reason why an MDoc document withing a DeviceResponse failed to validate.
 */
@Serializable
internal data class InvalidDocumentTO(
    val index: Int,
    val documentType: String,
    val errors: List<DocumentErrorTO>,
)

/**
 * The details of a validated MSO MDoc document.
 */
@Serializable
internal data class DocumentTO(
    val docType: String,
    val attributes: Map<String, JsonObject> = emptyMap(),
)

/**
 * The outcome of trying to validate a DeviceResponse.
 */
internal sealed interface DeviceResponseValidationResult {
    data class Valid(val documents: JsonArray) : DeviceResponseValidationResult
    data class Invalid(val error: ValidationErrorTO) : DeviceResponseValidationResult
}

/**
 * Tries to validate a value as an MSO MDoc DeviceResponse.
 */
internal class ValidateMsoMdocDeviceResponse(
    private val clock: Clock,
    private val parsePemEncodedX509CertificateChain: ParsePemEncodedX509CertificateChain,
    private val deviceResponseValidatorFactory: (X5CShouldBe?) -> DeviceResponseValidator,
) {
    suspend operator fun invoke(deviceResponse: String, issuerChain: String?): DeviceResponseValidationResult =
        either {
            val validator = deviceResponseValidator(issuerChain)
                .getOrElse {
                    raise(ValidationErrorTO.invalidIssuerChain())
                }

            val documents = validator.ensureValid(deviceResponse)
                .mapLeft { it.toValidationFailureTO() }
                .bind()
                .map { Json.encodeToJsonElement(it.toDocumentTO(clock)) }
                .let { JsonArray(it) }

            documents
        }.fold(
            ifLeft = { DeviceResponseValidationResult.Invalid(it) },
            ifRight = { DeviceResponseValidationResult.Valid(it) },
        )

    private fun deviceResponseValidator(issuerChainInPem: String?): Either<Throwable, DeviceResponseValidator> = Either.catch {
        val x5cShouldBe = issuerChainInPem
            ?.let { parsePemEncodedX509CertificateChain.x5cShouldBeTrustedOrNull(it).getOrThrow() }
        deviceResponseValidatorFactory(x5cShouldBe)
    }
}

private fun DeviceResponseError.toValidationFailureTO(): ValidationErrorTO =
    when (this) {
        DeviceResponseError.CannotBeDecoded -> ValidationErrorTO.cannotBeDecoded()
        is DeviceResponseError.NotOkDeviceResponseStatus -> ValidationErrorTO.notOkDeviceResponseStatus(status.toInt())
        is DeviceResponseError.InvalidDocuments -> ValidationErrorTO.invalidDocuments(invalidDocuments.map { it.toInvalidDocumentTO() })
    }

private fun InvalidDocument.toInvalidDocumentTO(): InvalidDocumentTO =
    InvalidDocumentTO(index, documentType, errors.map { it.toDocumentErrorTO() })

private fun DocumentError.toDocumentErrorTO(): DocumentErrorTO =
    when (this) {
        DocumentError.MissingValidityInfo -> DocumentErrorTO.MissingValidityInfo
        is DocumentError.ExpiredValidityInfo -> DocumentErrorTO.ExpiredValidityInfo
        DocumentError.IssuerKeyIsNotEC -> DocumentErrorTO.IssuerKeyIsNotEC
        DocumentError.InvalidIssuerSignature -> DocumentErrorTO.InvalidIssuerSignature
        is DocumentError.X5CNotTrusted -> DocumentErrorTO.X5CNotTrusted
        DocumentError.DocumentTypeNotMatching -> DocumentErrorTO.DocumentTypeNotMatching
        DocumentError.InvalidIssuerSignedItems -> DocumentErrorTO.InvalidIssuerSignedItems
        DocumentError.NoMatchingX5CShouldBe -> DocumentErrorTO.NoMatchingX5CValidator
        DocumentError.DocumentHasBeenRevoked -> DocumentErrorTO.DocumentHasBeenRevoked
        is DocumentError.DeviceKeyIsNotEC -> DocumentErrorTO.DeviceKeyIsNotEC
        is DocumentError.DeviceKeyNotAuthorizedToSignItems -> DocumentErrorTO.DeviceKeyNotAuthorizedToSignItems
        is DocumentError.DevicePublicKeyCannotBeParsed -> DocumentErrorTO.DevicePublicKeyCannotBeParsed
        DocumentError.InvalidDeviceSignature -> DocumentErrorTO.InvalidDeviceSignature
        DocumentError.MissingDeviceSigned -> DocumentErrorTO.MissingDeviceSigned
    }

private fun MDoc.toDocumentTO(clock: Clock): DocumentTO = DocumentTO(
    docType = docType.value,
    attributes = nameSpaces.associateWith { namespace ->
        buildJsonObject {
            getIssuerSignedItems(namespace).map { item ->
                put(item.elementIdentifier.value, item.elementValue.toJsonElement(clock))
            }
        }
    },
)

@OptIn(ExperimentalEncodingApi::class)
private val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

private fun Boolean.toJsonPrimitive() = JsonPrimitive(this)
private fun Number.toJsonPrimitive() = JsonPrimitive(this)
private fun String.toJsonPrimitive() = JsonPrimitive(this)
private fun List<JsonElement>.toJsonArray() = JsonArray(this)
private fun Map<String, JsonElement>.toJsonObject() = JsonObject(this)

@OptIn(ExperimentalEncodingApi::class)
private fun DataElement.toJsonElement(clock: Clock): JsonElement =
    when (this) {
        is BooleanElement -> value.toJsonPrimitive()
        is ByteStringElement -> base64.encode(value).toJsonPrimitive()
        is DateTimeElement -> value.toEpochMilliseconds().toJsonPrimitive()
        is EncodedCBORElement -> base64.encode(value).toJsonPrimitive()
        is FullDateElement -> value.atStartOfDayIn(clock.timeZone()).toEpochMilliseconds().toJsonPrimitive()
        is ListElement -> value.map { it.toJsonElement(clock) }.toJsonArray()
        is MapElement -> value.mapKeys { (key, _) -> key.str }.mapValues { (_, value) -> value.toJsonElement(clock) }.toJsonObject()
        is NullElement -> JsonNull
        is NumberElement -> value.toJsonPrimitive()
        is StringElement -> value.toJsonPrimitive()
        is TDateElement -> value.toEpochMilliseconds().toJsonPrimitive()

        // Other unsupported DataElements
        else -> this::class.java.simpleName.toJsonPrimitive()
    }
