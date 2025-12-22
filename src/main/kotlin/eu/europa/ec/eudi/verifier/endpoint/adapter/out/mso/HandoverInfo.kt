/*
 * Copyright (c) 2023 European Commission
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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseMode
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import java.net.URL

sealed interface HandoverInfo {

    data class OpenID4VPHandoverInfo(
        val clientId: VerifierId,
        val nonce: Nonce,
        val ephemeralEncryptionKey: JWK?,
        val responseUri: URL,
    ) : HandoverInfo {
        init {
            if (null != ephemeralEncryptionKey) {
                require(!ephemeralEncryptionKey.isPrivate) { "ephemeralEncryptionKey must not be private" }
            }
        }
    }

    data class OpenID4VPDCAPIHandoverInfo(
        val origin: URL,
        val nonce: Nonce,
        val ephemeralEncryptionKey: JWK?,
    ) : HandoverInfo {
        init {
            if (null != ephemeralEncryptionKey) {
                require(!ephemeralEncryptionKey.isPrivate) { "ephemeralEncryptionKey must not be private" }
            }
        }
    }

    companion object {
        operator fun invoke(
            presentation: Presentation.RequestObjectRetrieved,
            config: VerifierConfig,
        ): HandoverInfo = OpenID4VPHandoverInfo(
            clientId = config.verifierId,
            nonce = presentation.nonce,
            ephemeralEncryptionKey = when (val responseMode = presentation.responseMode) {
                ResponseMode.DirectPost -> null
                is ResponseMode.DirectPostJwt -> responseMode.ephemeralResponseEncryptionKey.toPublicJWK()
            },
            responseUri = config.responseUriBuilder(presentation.requestId),
        )
    }
}
