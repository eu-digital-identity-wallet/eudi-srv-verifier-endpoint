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
package eu.europa.ec.eudi.verifier.endpoint.port.out.x509

import arrow.core.NonEmptyList
import java.security.cert.X509Certificate

sealed interface AttestationIssuerTrust {
    data object Trusted : AttestationIssuerTrust
    data object NotTrusted : AttestationIssuerTrust
}

fun interface ValidateAttestationIssuerTrust {

    /**
     * Checks if the Issuer of an Attestation is trusted.
     *
     * @param issuerChain The Certificate Chain of the Issuer. Usually the 'x5c' claim.
     * @param attestationType The type of the Attestation. Either the `vct` or `docType`.
     */
    suspend operator fun invoke(issuerChain: NonEmptyList<X509Certificate>, attestationType: String): AttestationIssuerTrust

    companion object
}
