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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.*

sealed interface EncryptionRequirement {

    data object NotRequired : EncryptionRequirement

    data class Required(
        val recipientKey: JWK,
        val encryptionAlgorithm: JWEAlgorithm,
        val encryptionMethod: EncryptionMethod,
    ) : EncryptionRequirement {
        init {
            require(recipientKey.isSupportedEncryptionJwk()) { "unsupported jwk" }
            require(!recipientKey.isPrivate) { "jwk must not be private" }
            require(encryptionAlgorithm in recipientKey.supportedEncryptionAlgorithms) { "unsupported encryption algorithm" }
            require(encryptionMethod in recipientKey.supportedEncryptionMethods) { "unsupported encryption method" }
        }

        companion object
    }
}

internal fun JWK.isSupportedEncryptionJwk(): Boolean =
    if (null == keyUse || KeyUse.ENCRYPTION == keyUse) {
        when (this) {
            is RSAKey -> true
            is ECKey -> Curve.P_256 == curve || Curve.P_384 == curve || Curve.P_521 == curve
            is OctetKeyPair -> Curve.X25519 == curve
            else -> false
        }
    } else false

internal val JWK.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = when (this) {
        is RSAKey -> supportedEncryptionAlgorithms
        is ECKey -> supportedEncryptionAlgorithms
        is OctetKeyPair -> supportedEncryptionAlgorithms
        else -> error("Unsupported JWK type '${this::class.qualifiedName}'")
    }

internal val JWK.supportedEncryptionMethods: NonEmptyList<EncryptionMethod>
    get() = nonEmptyListOf(
        EncryptionMethod.A128CBC_HS256,
        EncryptionMethod.A192CBC_HS384,
        EncryptionMethod.A256CBC_HS512,
        EncryptionMethod.A128GCM,
        EncryptionMethod.A192GCM,
        EncryptionMethod.A256GCM,
        EncryptionMethod.XC20P,
    )

internal val RSAKey.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = nonEmptyListOf(
        JWEAlgorithm.RSA_OAEP_256,
        JWEAlgorithm.RSA_OAEP_384,
        JWEAlgorithm.RSA_OAEP_512,
    )

internal val ECKey.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = nonEmptyListOf(
        JWEAlgorithm.ECDH_ES,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A256KW,
    )

internal val OctetKeyPair.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = nonEmptyListOf(
        JWEAlgorithm.ECDH_ES,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A256KW,
    )

internal val encryptionMethodPreferenceMap = mapOf(
    EncryptionMethod.XC20P to 0,
    EncryptionMethod.A256GCM to 1,
    EncryptionMethod.A256CBC_HS512 to 2,
    EncryptionMethod.A192GCM to 3,
    EncryptionMethod.A192CBC_HS384 to 4,
    EncryptionMethod.A128GCM to 5,
    EncryptionMethod.A128CBC_HS256 to 6,
)

internal val encryptionAlgorithmPreferenceMap = mapOf(
    JWEAlgorithm.ECDH_ES_A256KW to 0,
    JWEAlgorithm.RSA_OAEP_512 to 0,
    JWEAlgorithm.ECDH_ES_A128KW to 1,
    JWEAlgorithm.RSA_OAEP_384 to 1,
    JWEAlgorithm.ECDH_ES_A128KW to 2,
    JWEAlgorithm.RSA_OAEP_256 to 2,
    JWEAlgorithm.ECDH_ES to 3,
)
