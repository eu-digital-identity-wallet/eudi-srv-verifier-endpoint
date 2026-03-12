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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation

import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationIdentifier
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation

suspend fun <CHAIN : Any, TRUST_ANCHOR : Any> IsChainTrustedForAttestation<CHAIN, TRUST_ANCHOR>.sdJwtVcIssuance(
    chain: CHAIN,
    vct: String,
): CertificationChainValidation<TRUST_ANCHOR>? = issuance(chain, AttestationIdentifier.SDJwtVc(vct))

suspend fun <CHAIN : Any, TRUST_ANCHOR : Any> IsChainTrustedForAttestation<CHAIN, TRUST_ANCHOR>.sdJwtVcRevocation(
    chain: CHAIN,
    vct: String,
): CertificationChainValidation<TRUST_ANCHOR>? = revocation(chain, AttestationIdentifier.SDJwtVc(vct))

suspend fun <CHAIN : Any, TRUST_ANCHOR : Any> IsChainTrustedForAttestation<CHAIN, TRUST_ANCHOR>.msoMdocIssuance(
    chain: CHAIN,
    docType: String,
): CertificationChainValidation<TRUST_ANCHOR>? = issuance(chain, AttestationIdentifier.MDoc(docType))

suspend fun <CHAIN : Any, TRUST_ANCHOR : Any> IsChainTrustedForAttestation<CHAIN, TRUST_ANCHOR>.msoMdocRevocation(
    chain: CHAIN,
    docType: String,
): CertificationChainValidation<TRUST_ANCHOR>? = revocation(chain, AttestationIdentifier.MDoc(docType))
