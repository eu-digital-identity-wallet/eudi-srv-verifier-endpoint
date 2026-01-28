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
package eu.europa.ec.eudi.verifier.endpoint.port.out.cfg

import arrow.core.Either
import arrow.core.NonEmptySet
import arrow.core.nonEmptySetOf
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.GetWalletResponseMethod
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseCode
import java.net.URI

fun interface CreateQueryWalletResponseRedirectUri {

    fun GetWalletResponseMethod.Redirect.redirectUri(responseCode: ResponseCode): URI =
        redirectUri(redirectUriTemplate, responseCode).getOrThrow()

    fun redirectUri(template: String, responseCode: ResponseCode): Either<Throwable, URI>

    fun String.validTemplate(): Boolean = redirectUri(this, ResponseCode("test")).isRight()

    companion object {
        const val RESPONSE_CODE_PLACE_HOLDER = "{RESPONSE_CODE}"

        fun simple(allowedSchemes: NonEmptySet<String>): CreateQueryWalletResponseRedirectUri =
            CreateQueryWalletResponseRedirectUri { template, responseCode ->
                Either.catch {
                    require(template.contains(RESPONSE_CODE_PLACE_HOLDER)) {
                        "Expected response_code place holder not found in template"
                    }
                    val uri = URI.create(template.replace(RESPONSE_CODE_PLACE_HOLDER, responseCode.value))
                    require(uri.scheme in allowedSchemes) {
                        "Disallowed scheme '${uri.scheme}' found in template. Allowed schemes: '${allowedSchemes.joinToString()}'."
                    }
                    uri
                }
            }

        fun simple(first: String, vararg remaining: String): CreateQueryWalletResponseRedirectUri = simple(nonEmptySetOf(first, *remaining))
    }
}
