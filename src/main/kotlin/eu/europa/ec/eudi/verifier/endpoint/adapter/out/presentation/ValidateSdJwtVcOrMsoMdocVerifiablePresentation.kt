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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.presentation

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.statium.TokenStatusListSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.SkipRevocation
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.digest.hash
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.HandoverInfo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidationError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.description
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.status
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist.StatusCheckException
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.dataelement.MapKeyType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(ValidateSdJwtVcOrMsoMdocVerifiablePresentation::class.java)

internal class ValidateSdJwtVcOrMsoMdocVerifiablePresentation(
    private val config: VerifierConfig,
    private val sdJwtVcValidatorFactory: (X5CShouldBe.Trusted?) -> SdJwtVcValidator,
    private val deviceResponseValidatorFactory: (X5CShouldBe.Trusted?) -> DeviceResponseValidator,
) : ValidateVerifiablePresentation {
    private val vpFormatsSupported = config.clientMetaData.vpFormatsSupported

    override suspend fun invoke(
        presentation: Presentation.RequestObjectRetrieved,
        verifiablePresentation: VerifiablePresentation,
        transactionData: NonEmptyList<TransactionData>?,
    ): Either<WalletResponseValidationError, VerifiablePresentation> = either {
        val issuerChain = presentation.issuerChain?.let { X5CShouldBe.Trusted(rootCACertificates = it, customizePKIX = SkipRevocation) }

        when (verifiablePresentation.format) {
            Format.SdJwtVc -> {
                val vpFormatSupported = checkNotNull(vpFormatsSupported.sdJwtVc)
                val validator = sdJwtVcValidatorFactory(issuerChain)
                validator.validateSdJwtVcVerifiablePresentation(
                    vpFormatSupported,
                    verifiablePresentation,
                    presentation.nonce,
                    transactionData,
                    presentation.id,
                    presentation.profile,
                ).bind()
            }

            Format.MsoMdoc -> {
                val vpFormatSupported = checkNotNull(vpFormatsSupported.msoMdoc)
                val validator = deviceResponseValidatorFactory(issuerChain)
                validator.validateMsoMdocVerifiablePresentation(
                    presentation,
                    verifiablePresentation,
                    vpFormatSupported,
                ).bind()
            }

            else ->
                throw IllegalArgumentException("unsupported format '${verifiablePresentation.format}'")
        }
    }

    private suspend fun SdJwtVcValidator.validateSdJwtVcVerifiablePresentation(
        vpFormatSupported: VpFormatsSupported.SdJwtVc,
        verifiablePresentation: VerifiablePresentation,
        nonce: Nonce,
        transactionData: NonEmptyList<TransactionData>?,
        transactionId: TransactionId,
        profile: Profile,
    ): Either<WalletResponseValidationError, VerifiablePresentation> = either {
        fun invalidVpToken(errors: NonEmptyList<SdJwtVcValidationError>): WalletResponseValidationError {
            val validationFailures = jsonSupport.encodeToString(errors.toJson())
            log.warn("Failed to validate SD-JWT VC: $validationFailures")
            return WalletResponseValidationError.InvalidVpToken(validationFailures)
        }

        val (sdJwt, kbJwt) = when (verifiablePresentation) {
            is VerifiablePresentation.Str -> validate(
                unverified = verifiablePresentation.value,
                nonce = nonce,
                transactionId = transactionId,
            )

            is VerifiablePresentation.Json -> validate(
                unverified = verifiablePresentation.value,
                nonce = nonce,
                transactionId = transactionId,
            )
        }.mapLeft { errors -> invalidVpToken(errors) }.bind()

        val status = sdJwt.status()
        if (Profile.HAIP == profile && null != status) {
            ensure(TokenStatusListSpec.STATUS_LIST in status) {
                WalletResponseValidationError.HAIPValidationError.SdJwtVcMustUseTokenStatusList
            }
        }

        // Validate that the signing algorithm of sd-jwt-vc matches the algorithm specified in the presentation query
        if (null != vpFormatSupported.sdJwtAlgorithms) {
            ensure(sdJwt.jwt.header.algorithm in vpFormatSupported.sdJwtAlgorithms) {
                WalletResponseValidationError.InvalidVpToken("SD-JWT not signed with a supported algorithm")
            }
        }

        // Validate that the signing algorithm of key binding JWT matches the algorithm specified in the presentation query
        if (null != vpFormatSupported.kbJwtAlgorithms) {
            ensure(kbJwt.header.algorithm in vpFormatSupported.kbJwtAlgorithms) {
                WalletResponseValidationError.InvalidVpToken("Keybinding JWT not signed with a supported algorithm")
            }
        }

        if (null != transactionData) {
            ensureValidTransactionDataHashes(kbJwt, transactionData, config.transactionDataHashAlgorithm) { error ->
                WalletResponseValidationError.InvalidVpToken(error)
            }
        }

        verifiablePresentation
    }

    private suspend fun DeviceResponseValidator.validateMsoMdocVerifiablePresentation(
        presentation: Presentation.RequestObjectRetrieved,
        verifiablePresentation: VerifiablePresentation,
        vpFormatSupported: VpFormatsSupported.MsoMdoc,
    ): Either<WalletResponseValidationError, VerifiablePresentation.Str> = either {
        ensure(verifiablePresentation is VerifiablePresentation.Str) {
            WalletResponseValidationError.InvalidVpToken("Mso MDoc VC must be a string.")
        }

        val handoverInfo = HandoverInfo(presentation, config)
        val documents = ensureValid(verifiablePresentation.value, presentation.id, handoverInfo)
            .mapLeft { error ->
                log.warn("Failed to validate MsoMdoc VC. Reason: '$error'")
                error.toWalletResponseValidationError()
            }
            .bind()

        if (Profile.HAIP == presentation.profile) {
            ensure(1 == documents.size) {
                WalletResponseValidationError.HAIPValidationError.DeviceResponseContainsMoreThanOneMDoc
            }
        }

        documents.forEach { document ->
            val issuerSignature = ensureNotNull(document.issuerSigned.issuerAuth) {
                WalletResponseValidationError.InvalidVpToken("DeviceResponse contains unsigned MSO MDoc documents")
            }

            if (null != vpFormatSupported.issuerAuthAlgorithms) {
                ensure(issuerSignature.algorithm in vpFormatSupported.issuerAuthAlgorithms.map { it.value }) {
                    WalletResponseValidationError.InvalidVpToken("IssuerSigned not signed with a supported algorithm")
                }
            }

            val deviceSignature = ensureNotNull(document.deviceSigned?.deviceAuth?.deviceSignature) {
                WalletResponseValidationError.InvalidVpToken("DeviceResponse contains MSO MDoc documents without Device signature")
            }

            if (null != vpFormatSupported.deviceAuthAlgorithms) {
                ensure(deviceSignature.algorithm in vpFormatSupported.deviceAuthAlgorithms.map { it.value }) {
                    WalletResponseValidationError.InvalidVpToken("DeviceSigned not signed with a supported algorithm")
                }
            }

            val issuerSignaturePayload = checkNotNull(issuerSignature.decodePayloadAs<MapElement>())
            val status = issuerSignaturePayload.value[MapKey(TokenStatusListSpec.STATUS)]
            if (Profile.HAIP == presentation.profile && status is MapElement) {
                val msoRevocationMechanisms = setOf("identifier_list", TokenStatusListSpec.STATUS_LIST)
                ensure(status.value.keys.all { MapKeyType.string == it.type && it.str in msoRevocationMechanisms }) {
                    WalletResponseValidationError.HAIPValidationError.UnsupportedMsoRevocationMechanism(
                        used = status.value.keys.map { it.toString() }.toSet(),
                        allowed = msoRevocationMechanisms,
                    )
                }
            }
        }
        verifiablePresentation
    }
}

private fun JWTClaimsSet.stringClaim(claim: String): Either<Throwable, String> =
    Either.catch {
        getStringClaim(claim)
    }

private fun JWTClaimsSet.stringListClaim(claim: String): Either<Throwable, List<String>> =
    Either.catch {
        getStringListClaim(claim)
    }

private fun <Error> Raise<Error>.ensureValidTransactionDataHashes(
    keyBindingJwt: SignedJWT,
    transactionData: NonEmptyList<TransactionData>,
    hashAlgorithm: HashAlgorithm,
    convert: (String) -> Error,
) {
    val actualHashAlgorithm = keyBindingJwt.jwtClaimsSet.stringClaim(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)
        .getOrElse {
            raise(convert(it.message ?: "'${OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS}' claim is not a string"))
        }
    ensure(hashAlgorithm.ianaName == actualHashAlgorithm) {
        convert("'${OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS}' must be '${hashAlgorithm.ianaName}'")
    }

    val expectedHashes = transactionData.map {
        val hash = hash(it.base64Url, hashAlgorithm)
        base64UrlNoPadding.encode(hash)
    }
    val actualHashes = keyBindingJwt.jwtClaimsSet.stringListClaim(OpenId4VPSpec.TRANSACTION_DATA_HASHES)
        .getOrElse {
            raise(convert(it.message ?: "'${OpenId4VPSpec.TRANSACTION_DATA_HASHES}' claim is not a string list"))
        }
    ensure(actualHashes.isNotEmpty() && actualHashes.size <= expectedHashes.size && expectedHashes.containsAll(actualHashes)) {
        convert("hashes of transaction data do not match the expected values")
    }
}

private fun DeviceResponseError.toWalletResponseValidationError(): WalletResponseValidationError.InvalidVpToken {
    val error = when (this) {
        DeviceResponseError.CannotBeDecoded -> "DeviceResponse cannot be decoded"
        is DeviceResponseError.InvalidDocuments -> {
            val deviceResponseErrors = invalidDocuments.joinToString { invalidDocument ->
                val documentErrors = invalidDocument.errors.joinToString()
                "Document at index '${invalidDocument.index}' with docType '${invalidDocument.documentType}' " +
                    "contains the following errors: '$documentErrors'"
            }

            "DeviceResponse contains invalid documents: $deviceResponseErrors"
        }
        is DeviceResponseError.NotOkDeviceResponseStatus -> "Unexpected DeviceResponse status: '$status'"
    }

    return WalletResponseValidationError.InvalidVpToken(error)
}

private fun Collection<SdJwtVcValidationError>.toJson(): JsonArray =
    JsonArray(
        map { error ->
            buildJsonObject {
                put("error", error.reason.name)
                val (description, cause) = when (val cause = error.cause) {
                    is SdJwtVerificationException -> cause.description to null
                    is StatusCheckException -> cause.reason to cause.causedBy
                    else -> "an unexpected error occurred${cause.message?.let { ": $it" } ?: ""}" to cause
                }
                put("description", description)
                cause?.message?.let { put("cause", it) }
            }
        },
    )
