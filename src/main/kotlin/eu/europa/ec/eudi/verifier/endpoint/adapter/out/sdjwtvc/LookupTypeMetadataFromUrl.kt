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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import arrow.core.Either
import eu.europa.ec.eudi.sdjwt.vc.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.toResult
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.decodeFromStream
import java.io.ByteArrayInputStream

class LookupTypeMetadataFromUrl(
    private val httpClient: HttpClient,
    private val vcts: Map<Vct, Url>,
    private val sriValidator: SRIValidator?,
) : LookupTypeMetadata {
    override suspend fun invoke(vct: Vct, expectedIntegrity: DocumentIntegrity?): Result<SdJwtVcTypeMetadata?> =
        Either.catch {
            vcts[vct]?.let { url ->
                val response = httpClient.get(url) {
                    expectSuccess = false
                }

                when (response.status) {
                    HttpStatusCode.OK -> {
                        val body = response.body<ByteArray>()
                        if (null != expectedIntegrity && null != sriValidator) {
                            check(sriValidator.isValid(expectedIntegrity, body)) {
                                "sub-resource integrity validation fails"
                            }
                        }

                        ByteArrayInputStream(body).use {
                            jsonSupport.decodeFromStream<SdJwtVcTypeMetadata>(it)
                        }
                    }
                    HttpStatusCode.NotFound -> null
                    else -> throw ResponseException(response, "Failed to retrieve type metadata")
                }
            }
        }.toResult()
}
