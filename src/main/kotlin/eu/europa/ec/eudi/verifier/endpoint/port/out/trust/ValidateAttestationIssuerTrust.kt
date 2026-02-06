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
package eu.europa.ec.eudi.verifier.endpoint.port.out.trust

import arrow.core.NonEmptyList
import java.security.cert.X509Certificate

sealed interface AttestationIdentifier {
    data class SdJwtVc(val vct: String) : AttestationIdentifier
    data class MsoMdoc(val docType: String) : AttestationIdentifier

    companion object {
        fun sdJwtVc(vct: String) = SdJwtVc(vct)
        fun msoMdoc(docType: String) = MsoMdoc(docType)
    }
}

sealed interface AttestationIssuerTrust {
    data object Trusted : AttestationIssuerTrust
    data object NotTrusted : AttestationIssuerTrust
}

fun interface ValidateAttestationIssuerTrust {

    /**
     * Checks if the Issuer of an Attestation is trusted.
     *
     * @param chain The Certificate Chain of the Issuer. Usually the 'x5c' claim.
     * @param identifier The identifier of the Attestation. Either the `vct` or `docType`.
     */
    suspend operator fun invoke(chain: NonEmptyList<X509Certificate>, identifier: AttestationIdentifier): AttestationIssuerTrust

    companion object
}
