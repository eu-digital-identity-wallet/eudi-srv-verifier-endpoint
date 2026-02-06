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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.trust

import arrow.core.NonEmptyList
import arrow.core.raise.catch
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation
import eu.europa.ec.eudi.etsi1196x2.consultation.MDoc
import eu.europa.ec.eudi.etsi1196x2.consultation.SDJwtVc
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import eu.europa.ec.eudi.verifier.endpoint.port.out.trust.AttestationIdentifier
import eu.europa.ec.eudi.verifier.endpoint.port.out.trust.AttestationIssuerTrust
import eu.europa.ec.eudi.verifier.endpoint.port.out.trust.ValidateAttestationIssuerTrust
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationIdentifier as ConsultationAttestationIdentifier

val ValidateAttestationIssuerTrust.Companion.Ignored: ValidateAttestationIssuerTrust
    get() = ValidateAttestationIssuerTrust { _, _ -> AttestationIssuerTrust.Trusted }

fun ValidateAttestationIssuerTrust.Companion.usingIssuerChain(
    x5cShouldBe: X5CShouldBe.Trusted,
): ValidateAttestationIssuerTrust {
    val validator: X5CValidator by lazy { X5CValidator(x5cShouldBe) }
    return ValidateAttestationIssuerTrust { chain, _ ->
        validator.ensureTrusted(chain)
            .fold(
                ifLeft = { AttestationIssuerTrust.NotTrusted },
                ifRight = { AttestationIssuerTrust.Trusted },
            )
    }
}

fun ValidateAttestationIssuerTrust.Companion.usingConsultation(
    isChainTrustedForAttestation: IsChainTrustedForAttestation<NonEmptyList<X509Certificate>, TrustAnchor>,
): ValidateAttestationIssuerTrust =
    ValidateAttestationIssuerTrust { chain, identifier ->
        catch({
            val result = isChainTrustedForAttestation.issuance(chain, identifier.toConsultationAttestationIdentifier())
            when (result) {
                is CertificationChainValidation.Trusted -> AttestationIssuerTrust.Trusted
                is CertificationChainValidation.NotTrusted -> AttestationIssuerTrust.NotTrusted
                null -> AttestationIssuerTrust.Unverified(IllegalStateException("Missing attestation classification for $identifier"))
            }
        }) { AttestationIssuerTrust.Unverified(it) }
    }

private fun AttestationIdentifier.toConsultationAttestationIdentifier(): ConsultationAttestationIdentifier =
    when (this) {
        is AttestationIdentifier.MsoMdoc -> MDoc(docType)
        is AttestationIdentifier.SdJwtVc -> SDJwtVc(vct)
    }
