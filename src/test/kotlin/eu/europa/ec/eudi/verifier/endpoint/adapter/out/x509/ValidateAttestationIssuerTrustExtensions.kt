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
import eu.europa.ec.eudi.verifier.endpoint.domain.MsoMdocDocType
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.AttestationIssuerTrust
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ValidateAttestationIssuerTrust
import java.security.cert.X509Certificate

val ValidateAttestationIssuerTrust.Companion.Ignored: ValidateAttestationIssuerTrust
    get() = object : ValidateAttestationIssuerTrust {
        override suspend fun invoke(
            issuerChain: NonEmptyList<X509Certificate>,
            vct: Vct,
        ): AttestationIssuerTrust = AttestationIssuerTrust.Trusted

        override suspend fun invoke(
            issuerChain: NonEmptyList<X509Certificate>,
            docType: MsoMdocDocType,
        ): AttestationIssuerTrust = AttestationIssuerTrust.Trusted
    }
