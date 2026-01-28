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

import arrow.core.Either
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.util.X509CertChainUtils
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509CertificateChain

/**
 * [ParsePemEncodedX509CertificateChain] implementation using Nimbus.
 */
internal val ParsePemEncodedX509CertificateChainWithNimbus = ParsePemEncodedX509CertificateChain { chain ->
    Either.catch {
        val certs = X509CertChainUtils.parse(chain).toNonEmptyListOrNull()
        requireNotNull(certs) { "Failed to parse certificates from PEM" }
    }
}
