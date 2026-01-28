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
package eu.europa.ec.eudi.verifier.endpoint.domain

import com.eygraber.uri.Uri
import com.eygraber.uri.toURI

@JvmInline
value class UnresolvedAuthorizationRequestUri private constructor(val value: Uri) {

    fun resolve(verifierId: VerifierId, request: Jwt): Uri =
        value.buildUpon()
            .appendQueryParameter(RFC6749.CLIENT_ID, verifierId.clientId)
            .appendQueryParameter(RFC9101.REQUEST, request)
            .build()

    fun resolve(verifierId: VerifierId, requestUri: Uri, requestUriMethod: RequestUriMethod): Uri =
        value.buildUpon()
            .appendQueryParameter(RFC6749.CLIENT_ID, verifierId.clientId)
            .appendQueryParameter(RFC9101.REQUEST_URI, requestUri.toURI().toString())
            .apply {
                val requestUriMethod = when (requestUriMethod) {
                    RequestUriMethod.Get -> OpenId4VPSpec.REQUEST_URI_METHOD_GET
                    RequestUriMethod.Post, RequestUriMethod.PostOrGet -> OpenId4VPSpec.REQUEST_URI_METHOD_POST
                }
                appendQueryParameter(OpenId4VPSpec.REQUEST_URI_METHOD, requestUriMethod)
            }
            .build()

    companion object {
        val DisallowedQueryParameters = setOf(RFC6749.CLIENT_ID, RFC9101.REQUEST, RFC9101.REQUEST_URI, OpenId4VPSpec.REQUEST_URI_METHOD)

        fun fromUri(value: String): Result<UnresolvedAuthorizationRequestUri> = runCatching {
            require(value.isNotBlank()) { "value cannot be blank" }
            val uri = Uri.parse(value)
            require(uri.getQueryParameterNames().none { it in DisallowedQueryParameters }) {
                "value must not contain any of the following query parameters: '${DisallowedQueryParameters.joinToString()}'"
            }
            UnresolvedAuthorizationRequestUri(uri)
        }

        fun fromScheme(scheme: String): Result<UnresolvedAuthorizationRequestUri> = runCatching {
            require(scheme.matches("^[A-Za-z][A-Za-z0-9+-.]*$".toRegex())) {
                "'$scheme' is not a valid URI scheme"
            }
            fromUri("$scheme://").getOrThrow()
        }
    }
}
