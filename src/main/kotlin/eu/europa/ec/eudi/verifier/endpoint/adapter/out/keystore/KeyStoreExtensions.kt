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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.keystore

import arrow.core.NonEmptyList
import arrow.core.some
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.util.Base64
import org.springframework.core.io.DefaultResourceLoader
import java.security.KeyStore
import java.security.cert.X509Certificate

fun loadKeyStore(location: String, type: String = KeyStore.getDefaultType(), password: String? = null): KeyStore {
    val keystoreResource = run {
        val keystoreResource = DefaultResourceLoader().getResource(location)
            .some()
            .filter { it.exists() }
            .getOrNull()
        checkNotNull(keystoreResource) { "Could not load Keystore from: '$location'" }
    }

    return keystoreResource.inputStream.use { inputStream ->
        val keystore = KeyStore.getInstance(type)
        keystore.load(inputStream, password?.toCharArray())
        keystore
    }
}

fun KeyStore.loadJWK(alias: String, password: String?): JWK {
    fun JWK.withCertificateChain(chain: NonEmptyList<X509Certificate>): JWK {
        val encodedChain = chain.map { Base64.encode(it.encoded) }
        return when (this) {
            is RSAKey -> RSAKey.Builder(this).x509CertChain(encodedChain).build()
            is ECKey -> ECKey.Builder(this).x509CertChain(encodedChain).build()
            is OctetKeyPair -> OctetKeyPair.Builder(this).x509CertChain(encodedChain).build()
            is OctetSequenceKey -> OctetSequenceKey.Builder(this).x509CertChain(encodedChain).build()
            else -> error("Unexpected JWK type '${this.keyType.value}'/'${this.javaClass}'")
        }
    }

    val jwk = JWK.load(this, alias, password?.toCharArray())
    val chain = getCertificateChain(alias)
        ?.mapNotNull { certificate -> certificate as? X509Certificate }
        ?.toNonEmptyListOrNull()
    requireNotNull(chain) { "Could not load Certificate chain for alias: $alias" }

    return jwk.withCertificateChain(chain)
}
