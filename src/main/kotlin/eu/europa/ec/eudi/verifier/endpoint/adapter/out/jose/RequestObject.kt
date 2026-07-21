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
import com.eygraber.uri.Url
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
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
    val verifierInfo: List<VerifierInfo>,
)

context(verifierConfig: VerifierConfig)
internal fun requestObjectFromDomain(
    issuedAt: Instant,
    transactionData: NonEmptyList<TransactionData>?,
    channel: Channel,
    query: DCQL,
    nonce: Nonce,
    registrationCertificate: RegistrationCertificate,
): RequestObject {
    val scope = emptyList<String>()
    val responseType = listOf(OpenId4VPSpec.VP_TOKEN)
    val audience = listOf("https://self-issued.me/v2")
    val transactionData = transactionData?.map { it.base64Url }
    val verifierInfo = VerifierInfo(format = ETSI119472Part2.REGISTRATION_CERTIFICATE, data = registrationCertificate.value.serialize())

    return when (channel) {
        is Channel.OverDcApi -> {
            RequestObject(
                verifierId = verifierConfig.verifierId,
                scope = scope,
                query = query,
                responseType = responseType,
                audience = audience,
                nonce = nonce.value,
                state = null,
                responseMode = OpenId4VPSpec.RESPONSE_MODE_DCAPI_JWT,
                responseUri = null,
                issuedAt = issuedAt,
                transactionData = transactionData,
                expectedOrigins = channel.expectedOrigins,
                verifierInfo = listOf(verifierInfo),
            )
        }

        is Channel.OverHttp -> {
            when (channel.responseMode) {
                ResponseMode.OverHttp.DirectPost -> {
                    RequestObject(
                        verifierId = verifierConfig.verifierId,
                        scope = scope,
                        query = query,
                        responseType = responseType,
                        audience = audience,
                        nonce = nonce.value,
                        state = channel.requestId.value,
                        responseMode = OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST,
                        responseUri = verifierConfig.responseUriBuilder(channel.requestId),
                        issuedAt = issuedAt,
                        transactionData = transactionData,
                        expectedOrigins = null,
                        verifierInfo = listOf(verifierInfo),
                    )
                }

                is ResponseMode.OverHttp.DirectPostJwt -> {
                    RequestObject(
                        verifierId = verifierConfig.verifierId,
                        scope = scope,
                        query = query,
                        responseType = responseType,
                        audience = audience,
                        nonce = nonce.value,
                        state = channel.requestId.value,
                        responseMode = OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT,
                        responseUri = verifierConfig.responseUriBuilder(channel.requestId),
                        issuedAt = issuedAt,
                        transactionData = transactionData,
                        expectedOrigins = null,
                        verifierInfo = listOf(verifierInfo),
                    )
                }
            }
        }
    }
}

@Serializable
data class VerifierInfo(
    @Required @SerialName(OpenId4VPSpec.VERIFIER_INFO_FORMAT)
    val format: String,
    @Required @SerialName(OpenId4VPSpec.VERIFIER_INFO_DATA)
    val data: String,
)
