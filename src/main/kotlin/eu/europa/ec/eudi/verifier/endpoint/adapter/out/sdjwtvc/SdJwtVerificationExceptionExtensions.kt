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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import eu.europa.ec.eudi.sdjwt.KeyBindingError
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.sdjwt.VerificationError
import eu.europa.ec.eudi.sdjwt.dsl.def.DefinitionViolation
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport

internal val SdJwtVerificationException.description: String
    get() = descriptionOf(reason)

private fun descriptionOf(sdJwtError: VerificationError): String = when (sdJwtError) {
    VerificationError.ParsingError -> "sd-jwt could not be parsed"
    is VerificationError.InvalidJwt ->
        joinNotBlank("sd-jwt contains an invalid jwt", sdJwtError.message, descriptionOf(sdJwtError.cause))
    is VerificationError.KeyBindingFailed -> sdJwtError.description
    is VerificationError.InvalidDisclosures -> {
        val invalidDDisclosures = sdJwtError.invalidDisclosures.map {
            "${it.key} : ${it.value.joinToString()}"
        }.joinToString()
        "sd-jwt contains invalid disclosures: $invalidDDisclosures"
    }
    is VerificationError.UnsupportedHashingAlgorithm -> "sd-jwt contains an unsupported hash algorithm: ${sdJwtError.algorithm}"
    is VerificationError.NonUniqueDisclosures -> {
        val nonUniqueDisclosures = sdJwtError.nonUniqueDisclosures.joinToString()
        "sd-jwt contains non-unique disclosures: $nonUniqueDisclosures"
    }
    VerificationError.NonUniqueDisclosureDigests -> "sd-jwt contains non-unique digests"
    is VerificationError.MissingDigests -> "sd-jwt contains disclosures for non-existing digests"
    is VerificationError.SdJwtVcError -> when (val sdJwtVcError = sdJwtError.error) {
        is IssuerKeyVerificationError -> sdJwtVcError.description
        is TypeMetadataVerificationError -> sdJwtVcError.description
    }
}

internal val VerificationError.KeyBindingFailed.description
    get() = when (val details = details) {
        KeyBindingError.MissingHolderPublicKey -> "missing holder public key (cnf)"
        KeyBindingError.UnsupportedHolderPublicKey -> "unsupported holder public key (cnf) type"
        is KeyBindingError.InvalidKeyBindingJwt ->
            joinNotBlank("keybinding jwt is not valid", details.message, descriptionOf(details.cause))
        KeyBindingError.UnexpectedKeyBindingJwt -> "keybinding jwt was not expected"
        KeyBindingError.MissingKeyBindingJwt -> "missing keybinding jwt"
    }

internal val SdJwtVcVerificationError.IssuerKeyVerificationError.description: String
    get() = when (this) {
        is IssuerKeyVerificationError.UnsupportedVerificationMethod ->
            "sd-jwt vc requires $method, but this verification method is not enabled"

        is IssuerKeyVerificationError.IssuerMetadataResolutionFailure ->
            joinNotBlank("unable to resolve sd-jwt vc issuer metadata", descriptionOf(cause))

        is IssuerKeyVerificationError.UntrustedIssuerCertificate ->
            joinNotBlank("sd-jwt vc issuer certificate is not trusted", reason)

        is IssuerKeyVerificationError.DIDLookupFailure ->
            joinNotBlank("did lookup failed", message, descriptionOf(cause))

        IssuerKeyVerificationError.CannotDetermineIssuerVerificationMethod ->
            "cannot determine verification method for sd-jwt vc. missing 'x5c' header claim, issuer is not an https url or did"
    }

internal val SdJwtVcVerificationError.TypeMetadataVerificationError.description: String
    get() = when (this) {
        is TypeMetadataVerificationError.TypeMetadataResolutionFailure ->
            joinNotBlank("unable to resolve sd-jwt vc type metadata", descriptionOf(cause))
        is TypeMetadataVerificationError.TypeMetadataValidationFailure -> {
            val definitionViolations = errors.joinToString { it.description }
            joinNotBlank("sd-jwt vc could not be validated according to its type metadata", definitionViolations)
        }
    }

internal val DefinitionViolation.description: String
    get() = when (this) {
        is DefinitionViolation.DisclosureInconsistencies ->
            joinNotBlank("contains disclosure inconsistencies", descriptionOf(cause))
        is DefinitionViolation.IncorrectlyDisclosedClaim ->
            "contains a claim that has not been properly disclosed at claim path ${jsonSupport.encodeToString(claimPath)}"
        is DefinitionViolation.InvalidVct ->
            "has an invalid vct. expected: '${expected.value}', found: '$actual'"
        is DefinitionViolation.MissingRequiredClaim ->
            "is missing the following required claim ${jsonSupport.encodeToString(claimPath)}"
        is DefinitionViolation.UnknownClaim ->
            "contains an unknown claim at claim path ${jsonSupport.encodeToString(claimPath)}"
        is DefinitionViolation.WrongClaimType ->
            "contains a claim with incorrect type at claim path ${jsonSupport.encodeToString(claimPath)}"
    }

private fun joinNotBlank(vararg values: String?): String = values.filterNot { it.isNullOrBlank() }.joinToString(", ")

private fun descriptionOf(error: Throwable?): String? =
    when (error) {
        is SdJwtVerificationException -> descriptionOf(error.reason)
        else -> error?.message
    }
