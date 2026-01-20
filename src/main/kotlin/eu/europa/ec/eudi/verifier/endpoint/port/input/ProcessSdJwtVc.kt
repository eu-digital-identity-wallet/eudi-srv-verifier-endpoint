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
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.RFC9901
import eu.europa.ec.eudi.sdjwt.SdJwtVcVerifier
import eu.europa.ec.eudi.sdjwt.vc.IssuerVerificationMethod
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerifier
import eu.europa.ec.eudi.sdjwt.vc.TypeMetadataPolicy
import kotlinx.serialization.json.JsonObject

class ProcessSdJwtVc {
    private val verifier = DefaultSdJwtOps.SdJwtVcVerifier(
        IssuerVerificationMethod.usingCustom(DefaultSdJwtOps.NoSignatureValidation),
        TypeMetadataPolicy.NotUsed,
    )

    suspend operator fun invoke(unprocessed: String): Either<Throwable, JsonObject> = Either.catch {
        if (unprocessed.endsWith(RFC9901.DISCLOSURE_SEPARATOR)) {
            verifier.processWithoutKeyBinding(unprocessed)
        } else {
            verifier.processWithKeyBinding(unprocessed)
        }
    }

    private suspend fun SdJwtVcVerifier<JwtAndClaims>.processWithoutKeyBinding(unprocessed: String): JsonObject {
        val sdJwt = verify(unprocessed).getOrThrow()
        val (processed, _) = with(DefaultSdJwtOps) {
            sdJwt.recreateClaimsAndDisclosuresPerClaim()
        }
        return processed
    }

    private suspend fun SdJwtVcVerifier<JwtAndClaims>.processWithKeyBinding(unprocessed: String): JsonObject {
        val (sdJwt, _) = verify(unprocessed, challenge = null).getOrThrow()
        val (processed, _) = with(DefaultSdJwtOps) {
            sdJwt.recreateClaimsAndDisclosuresPerClaim()
        }
        return processed
    }
}
