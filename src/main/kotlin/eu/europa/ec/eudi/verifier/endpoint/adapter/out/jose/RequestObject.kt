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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import com.eygraber.uri.Url
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import java.net.URL
import kotlin.time.Instant

internal data class RequestObject(
    val verifierId: VerifierId,
    val responseType: List<String>,
    val query: DCQL,
    val scope: List<String>,
    val nonce: String,
    val responseMode: String,
    val responseUri: URL?,
    val audience: List<String>,
    val state: String?,
    val issuedAt: Instant,
    val transactionData: List<String>? = null,
    val expectedOrigins: List<Url>? = null,
)

internal fun requestObjectFromDomain(
    verifierConfig: VerifierConfig,
    clock: Clock,
    presentation: Presentation.Requested,
): RequestObject {
    val scope = emptyList<String>()
    val responseType = listOf(OpenId4VPSpec.VP_TOKEN)
    val aud = listOf("https://self-issued.me/v2")
    val transactionData = presentation.transactionData?.map { it.base64Url }
    return when (val channel = presentation.channel) {
        is Channel.OverDcApi -> {
            RequestObject(
                verifierId = verifierConfig.verifierId,
                scope = scope,
                query = presentation.query,
                responseType = responseType,
                audience = aud,
                nonce = presentation.nonce.value,
                state = null,
                responseMode = OpenId4VPSpec.RESPONSE_MODE_DCAPI_JWT,
                responseUri = null,
                issuedAt = clock.now(),
                transactionData = transactionData,
                expectedOrigins = listOf(channel.origin),
            )
        }

        is Channel.OverHttp -> {
            when (presentation.channel.responseMode) {
                ResponseMode.OverHttp.DirectPost -> {
                    RequestObject(
                        verifierId = verifierConfig.verifierId,
                        scope = scope,
                        query = presentation.query,
                        responseType = responseType,
                        audience = aud,
                        nonce = presentation.nonce.value,
                        state = presentation.channel.requestId.value,
                        responseMode = OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST,
                        responseUri = verifierConfig.responseUriBuilder(presentation.channel.requestId),
                        issuedAt = clock.now(),
                        transactionData = transactionData,
                        expectedOrigins = null,
                    )
                }

                is ResponseMode.OverHttp.DirectPostJwt -> {
                    RequestObject(
                        verifierId = verifierConfig.verifierId,
                        scope = scope,
                        query = presentation.query,
                        responseType = responseType,
                        audience = aud,
                        nonce = presentation.nonce.value,
                        state = presentation.channel.requestId.value,
                        responseMode = OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT,
                        responseUri = verifierConfig.responseUriBuilder(presentation.channel.requestId),
                        issuedAt = clock.now(),
                        transactionData = transactionData,
                        expectedOrigins = null,
                    )
                }
            }
        }
    }
}
