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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert

import arrow.core.Either
import arrow.core.Nel
import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import java.security.KeyStore
import java.security.cert.*

typealias ConfigurePKIXParameters = PKIXParameters.() -> Unit

internal val SkipRevocation: ConfigurePKIXParameters = { isRevocationEnabled = false }

/**
 * Options about [certificate chain validator][X5CValidator]
 */
sealed interface X5CShouldBe {

    /**
     * The chain should be trusted
     *
     * @param rootCACertificates list of trusted root CA certificates. To be used as trust anchors
     * @param customizePKIX a way to parameterize [PKIXParameters]. If not provided, revocation checks are disabled
     */
    data class Trusted(
        val rootCACertificates: NonEmptyList<X509Certificate>,
        val customizePKIX: ConfigurePKIXParameters = SkipRevocation,
    ) : X5CShouldBe

    /**
     * The chain will not be checked
     */
    data object Ignored : X5CShouldBe

    fun caCertificates(): List<X509Certificate> =
        when (this) {
            Ignored -> emptyList()
            is Trusted -> rootCACertificates
        }

    companion object {
        operator fun invoke(
            rootCACertificates: List<X509Certificate>,
            customizePKIX: ConfigurePKIXParameters = SkipRevocation,
        ): X5CShouldBe =
            when (val nel = rootCACertificates.toNonEmptyListOrNull()) {
                null -> Ignored
                else -> Trusted(nel, customizePKIX)
            }

        fun fromKeystore(
            trustedCAsKeyStore: KeyStore,
            customizePKIX: ConfigurePKIXParameters = SkipRevocation,
        ): X5CShouldBe {
            val trustedRootCAs = trustedCAs(trustedCAsKeyStore)
            return X5CShouldBe(trustedRootCAs, customizePKIX)
        }

        internal fun trustedCAs(keystore: KeyStore): List<X509Certificate> {
            fun x509(alias: String) =
                alias.takeIf(keystore::isCertificateEntry)
                    ?.let(keystore::getCertificate) as? X509Certificate

            return buildList {
                for (alias in keystore.aliases()) {
                    x509(alias)?.let(::add)
                }
            }
        }
    }
}

class X5CValidator(private val x5CShouldBe: X5CShouldBe) {

    fun ensureTrusted(
        chain: Nel<X509Certificate>,
    ): Either<CertPathValidatorException, Nel<X509Certificate>> =
        Either.catchOrThrow {
            trustedOrThrow(chain)
            chain
        }

    @Throws(CertPathValidatorException::class)
    fun trustedOrThrow(chain: Nel<X509Certificate>) {
        when (x5CShouldBe) {
            X5CShouldBe.Ignored -> Unit // Do nothing
            is X5CShouldBe.Trusted -> {
                trustedOrThrow(chain, x5CShouldBe)
            }
        }
    }
}

@Throws(CertPathValidatorException::class)
private fun trustedOrThrow(
    chain: Nel<X509Certificate>,
    trusted: X5CShouldBe.Trusted,
) {
    val factory = CertificateFactory.getInstance("X.509")
    val certPath = factory.generateCertPath(chain)

    val pkixParameters = trusted.asPkixParameters()
    val validator = CertPathValidator.getInstance("PKIX")

    validator.validate(certPath, pkixParameters)
}

private fun X5CShouldBe.Trusted.asPkixParameters(): PKIXParameters {
    val trust = rootCACertificates.map { cert -> TrustAnchor(cert, null) }.toSet()
    return PKIXParameters(trust).apply(customizePKIX)
}
