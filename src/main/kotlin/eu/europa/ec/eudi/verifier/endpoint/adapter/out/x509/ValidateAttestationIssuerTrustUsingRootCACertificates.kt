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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509

import arrow.core.NonEmptyList
import eu.europa.ec.eudi.sdjwt.vc.Vct
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.MsoMdocDocType
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.AttestationIssuerTrust
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ValidateAttestationIssuerTrust
import java.security.cert.X509Certificate

private class ValidateAttestationIssuerTrustUsingRootCACertificates(x5cShouldBe: X5CShouldBe.Trusted) : ValidateAttestationIssuerTrust {
    private val validator: X5CValidator by lazy { X5CValidator(x5cShouldBe) }

    override suspend fun invoke(
        issuerChain: NonEmptyList<X509Certificate>,
        vct: Vct,
    ): AttestationIssuerTrust = validator.checkIssuerTrust(issuerChain)

    override suspend fun invoke(
        issuerChain: NonEmptyList<X509Certificate>,
        docType: MsoMdocDocType,
    ): AttestationIssuerTrust = validator.checkIssuerTrust(issuerChain)
}

private fun X5CValidator.checkIssuerTrust(issuerChain: NonEmptyList<X509Certificate>): AttestationIssuerTrust =
    ensureTrusted(issuerChain)
        .fold(
            ifLeft = { AttestationIssuerTrust.NotTrusted },
            ifRight = { AttestationIssuerTrust.Trusted },
        )

fun ValidateAttestationIssuerTrust.Companion.usingRootCACertificates(
    x5cShouldBe: X5CShouldBe.Trusted,
): ValidateAttestationIssuerTrust = ValidateAttestationIssuerTrustUsingRootCACertificates(x5cShouldBe)
