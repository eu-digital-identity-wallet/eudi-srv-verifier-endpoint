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
package eu.europa.ec.eudi.verifier.endpoint.port.out.lotl

import arrow.core.Either
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedListConfig
import java.security.cert.X509Certificate

/**
 * Interface for fetching LOTL certificates
 */
fun interface FetchLOTLCertificates {
    /**
     * Fetch certificates from a LOTL URL
     * @param trustedListConfig Configuration for the trusted list
     * @return Result containing a list of X509 certificates or an exception
     */
    suspend operator fun invoke(
        trustedListConfig: TrustedListConfig,
    ): Either<Throwable, List<X509Certificate>>
}
