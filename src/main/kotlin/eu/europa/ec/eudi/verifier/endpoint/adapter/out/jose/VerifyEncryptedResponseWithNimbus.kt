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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.raise
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.AuthorisationResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyEncryptedResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Decrypts an encrypted JWT and maps the JWT claimSet to an AuthorisationResponseTO
 */
class VerifyEncryptedResponseWithNimbus(
    private val responseEncryptionOption: ResponseEncryptionOption,
) : VerifyEncryptedResponse {
    context(_: Raise<WalletResponseValidationError.InvalidEncryptedResponse>)
    override suspend fun invoke(
        ephemeralResponseEncryptionKey: JWK,
        encryptedResponse: Jwt,
        apv: Nonce,
    ): AuthorisationResponseTO =
        withContext(Dispatchers.Default) {
            catch(
                block = {
                    val encryptedJwt = EncryptedJWT.parse(encryptedResponse)
                    val processor = encryptedProcessor(ephemeralResponseEncryptionKey, encryptedJwt)
                    val claimSet = processor.process(encryptedJwt, null)
                    claimSet.mapToDomain()
                },
                catch = { throwable ->
                    if (throwable is Exception) {
                        raise(WalletResponseValidationError.InvalidEncryptedResponse(throwable))
                    } else {
                        throw throwable
                    }
                },
            )
        }

    private fun encryptedProcessor(
        ephemeralResponseEncryptionKey: JWK,
        encryptedJwt: EncryptedJWT,
    ): JWTProcessor<SecurityContext> {
        with(encryptedJwt.header) {
            require(algorithm == responseEncryptionOption.algorithm) {
                "Encrypted response uses an unsupported JWE Algorithm: ${algorithm.name}, " +
                    "expected: ${responseEncryptionOption.algorithm.name}"
            }
            require(encryptionMethod in responseEncryptionOption.encryptionMethods) {
                "Encrypted response uses an unsupported JWE Encryption Method: ${encryptionMethod.name}, " +
                    "expected one of: ${responseEncryptionOption.encryptionMethods.joinToString { it.name }}"
            }

            return encryptedProcessor(algorithm, encryptionMethod, ephemeralResponseEncryptionKey)
        }
    }

    private fun encryptedProcessor(
        algorithm: JWEAlgorithm,
        method: EncryptionMethod,
        ephemeralResponseEncryptionKey: JWK,
    ): JWTProcessor<SecurityContext> =
        DefaultJWTProcessor<SecurityContext>().apply {
            jweKeySelector =
                JWEDecryptionKeySelector(
                    algorithm,
                    method,
                    ImmutableJWKSet(JWKSet(ephemeralResponseEncryptionKey)),
                )
        }

    @Suppress("UNCHECKED_CAST")
    private fun JWTClaimsSet.mapToDomain(): AuthorisationResponseTO =
        AuthorisationResponseTO(
            state = getClaim(RFC6749.STATE)?.toString(),
            vpToken =
                getJSONObjectClaim(OpenId4VPSpec.VP_TOKEN)
                    ?.let { vpToken ->
                        Json.decodeFromString<JsonObject>(JSONObjectUtils.toJSONString(vpToken))
                    },
            error = getClaim(RFC6749.ERROR)?.toString(),
            errorDescription = getClaim(RFC6749.ERROR_DESCRIPTION)?.toString(),
        )
}
