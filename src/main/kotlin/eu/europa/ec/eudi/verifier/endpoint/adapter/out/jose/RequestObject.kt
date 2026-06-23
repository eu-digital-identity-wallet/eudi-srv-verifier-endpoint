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

import arrow.core.NonEmptyList
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import java.net.URL
import kotlin.time.Instant

internal data class RequestObject(
    val verifierId: VerifierId,
    val responseType: List<String>,
    val dcqlQuery: DCQL? = null,
    val scope: List<String>,
    val nonce: String,
    val responseMode: String,
    val responseUri: URL?,
    val aud: List<String>,
    val state: String,
    val issuedAt: Instant,
    val transactionData: List<String>? = null,
    val expectedOrigins: List<String>? = null,
    val verifierInfo: VerifierInfo? = null,
)

internal data class VerifierInfo(
    val format: String,
    val data: String,
    val credentialIds: NonEmptyList<String>?,
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

    val (responseMode, requestId, expectedOrigins) =
        when (val z = presentation.channel) {
            is Channel.OverDcApi -> {
                Triple(OpenId4VPSpec.RESPONSE_MODE_DCAPI_JWT, null, z.expectedOrigins)
            }

            is Channel.OverHttp -> {
                when (presentation.channel.responseMode) {
                    ResponseMode.OverHttp.DirectPost -> {
                        Triple(
                            OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST,
                            presentation.requestId,
                            null,
                        )
                    }

                    is ResponseMode.OverHttp.DirectPostJwt -> {
                        Triple(
                            OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT,
                            presentation.requestId,
                            null,
                        )
                    }
                }
            }
        }
    return RequestObject(
        verifierId = verifierConfig.verifierId,
        scope = scope,
        dcqlQuery = presentation.query,
        responseType = responseType,
        aud = aud,
        nonce = presentation.nonce.value,
        state = presentation.requestId.value,
        responseMode = responseMode,
        responseUri =
            if (requestId != null)
                verifierConfig.responseUriBuilder(
                    presentation.requestId,
                )
            else
                null,
        issuedAt = clock.now(),
        transactionData = transactionData,
        expectedOrigins = expectedOrigins,
        verifierInfo = null,
    )
}
