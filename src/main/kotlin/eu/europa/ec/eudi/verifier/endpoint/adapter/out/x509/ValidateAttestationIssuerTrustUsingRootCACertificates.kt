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

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.AttestationIssuerTrust
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ValidateAttestationIssuerTrust

fun ValidateAttestationIssuerTrust.Companion.usingRootCACertificates(
    x5cShouldBe: X5CShouldBe.Trusted,
): ValidateAttestationIssuerTrust {
    val validator: X5CValidator by lazy { X5CValidator(x5cShouldBe) }
    return ValidateAttestationIssuerTrust { issuerChain, _ ->
        validator.ensureTrusted(issuerChain)
            .fold(
                ifLeft = { AttestationIssuerTrust.NotTrusted },
                ifRight = { AttestationIssuerTrust.Trusted },
            )
    }
}
