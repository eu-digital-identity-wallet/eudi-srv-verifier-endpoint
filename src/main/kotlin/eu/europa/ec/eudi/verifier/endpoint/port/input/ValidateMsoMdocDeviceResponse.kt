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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.getOrElse
import arrow.core.raise.either
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.InvalidDocument
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509Certificates
import id.walt.mdoc.namespaces.MdocSignedMerger
import id.walt.mdoc.objects.document.Document
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate

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
    NoMatchingX5CValidator,
    X5CNotTrusted,
    CannotBeDecoded,
    ExpiredValidityInfo,
    DocumentTypeNotMatching,
    InvalidIssuerSignedItems,
    UnsupportedKeyType,
    InvalidIssuerSignature,
    DocumentHasBeenRevoked,
    MissingDeviceSigned,
    DeviceKeyNotAuthorizedToSignItems,
    InvalidDeviceSignature,
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
    val attributes: JsonObject,
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
    private val parsePemEncodedX509Certificates: ParsePemEncodedX509Certificates,
    private val deviceResponseValidatorFactory: (NonEmptyList<X509Certificate>?) -> DeviceResponseValidator,
) {
    suspend operator fun invoke(deviceResponse: String, issuerChain: String?): DeviceResponseValidationResult = either {
        val validator = deviceResponseValidator(issuerChain)
            .getOrElse {
                return DeviceResponseValidationResult.Invalid(ValidationErrorTO.invalidIssuerChain())
            }

        val documents = validator.ensureValid(deviceResponse)
            .mapLeft { it.toValidationFailureTO() }
            .bind()
            .map { Json.encodeToJsonElement(it.toDocumentTO()) }
            .let { JsonArray(it) }

        documents
    }.fold(
        ifLeft = { DeviceResponseValidationResult.Invalid(it) },
        ifRight = { DeviceResponseValidationResult.Valid(it) },
    )

    private fun deviceResponseValidator(issuerChainInPem: String?): Either<Throwable, DeviceResponseValidator> = Either.catch {
        deviceResponseValidatorFactory(
            issuerChainInPem?.let { parsePemEncodedX509Certificates(it).getOrThrow() },
        )
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
        DocumentError.NoMatchingX5CShouldBe -> DocumentErrorTO.NoMatchingX5CValidator
        is DocumentError.X5CNotTrusted -> DocumentErrorTO.X5CNotTrusted
        DocumentError.CannotBeDecoded -> DocumentErrorTO.CannotBeDecoded
        is DocumentError.ExpiredValidityInfo -> DocumentErrorTO.ExpiredValidityInfo
        DocumentError.DocumentTypeNotMatching -> DocumentErrorTO.DocumentTypeNotMatching
        DocumentError.InvalidIssuerSignedItems -> DocumentErrorTO.InvalidIssuerSignedItems
        DocumentError.UnsupportedKeyType -> DocumentErrorTO.UnsupportedKeyType
        DocumentError.InvalidIssuerSignature -> DocumentErrorTO.InvalidIssuerSignature
        DocumentError.DocumentHasBeenRevoked -> DocumentErrorTO.DocumentHasBeenRevoked
        DocumentError.MissingDeviceSigned -> DocumentErrorTO.MissingDeviceSigned
        is DocumentError.DeviceKeyNotAuthorizedToSignItems -> DocumentErrorTO.DeviceKeyNotAuthorizedToSignItems
        DocumentError.InvalidDeviceSignature -> DocumentErrorTO.InvalidDeviceSignature
    }

private fun Document.toDocumentTO(): DocumentTO = DocumentTO(
    docType = docType,
    attributes = run {
        val issuerSigned = issuerSigned.namespacesToJson()
        deviceSigned?.namespaces?.value?.namespacesToJson()?.let { deviceSigned ->
            MdocSignedMerger.merge(
                issuerSigned,
                deviceSigned,
                strategy = MdocSignedMerger.MdocDuplicatesMergeStrategy.OVERRIDE,
            )
        } ?: issuerSigned
    },
)
