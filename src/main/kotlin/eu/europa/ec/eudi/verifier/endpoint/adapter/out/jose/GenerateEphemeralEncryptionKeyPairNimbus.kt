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

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseEncryptionOption
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.*

/**
 * An implementation of [GenerateEphemeralEncryptionKeyPair] that uses Nimbus SDK
 */
class GenerateEphemeralEncryptionKeyPairNimbus(
    private val responseEncryptionOption: ResponseEncryptionOption,
) : GenerateEphemeralEncryptionKeyPair {
    override suspend fun invoke(): JWK =
        withContext(Dispatchers.Default) {
            val alg = responseEncryptionOption.algorithm
            createEphemeralEncryptionKey(alg)
        }

    private fun createEphemeralEncryptionKey(alg: JWEAlgorithm): ECKey {
        val ecKeyGenerator =
            ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(alg)
                .keyID(UUID.randomUUID().toString())
        return ecKeyGenerator.generate()
    }
}
