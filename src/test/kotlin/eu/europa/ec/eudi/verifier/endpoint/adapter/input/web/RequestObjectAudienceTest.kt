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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import eu.europa.ec.eudi.verifier.endpoint.port.input.EmbedModeTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.RequestUriMethodTO
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * Verifies the JAR `aud` claim per OpenID4VP
 * - Dynamic Discovery (POST + `wallet_metadata` with `issuer`) -> `aud` = the Wallet's `issuer`.
 * - Static Discovery (GET, or POST without `issuer`) -> `aud` = `https://self-issued.me/v2`.
 */
@VerifierApplicationTest
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.defaultHttpResponseMode=DirectPostJwt",
    ],
)
internal class RequestObjectAudienceTest {
    @Autowired
    private lateinit var client: WebTestClient

    @Test
    fun `when wallet posts wallet_metadata, the created JAR aud claim is the wallet issuer`() =
        runTest {
            val initTransaction =
                VerifierApiClient
                    .loadInitTransactionTO("02-dcql.json")
                    .copy(jarMode = EmbedModeTO.ByReference, requestUriMethod = RequestUriMethodTO.Post)
            val transactionInitialized =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, initTransaction),
                )

            val walletMetadata =
                buildJsonObject {
                    put("issuer", "https://wallet.example")
                    putValidWalletMetadata()
                }.toString()

            val requestObject =
                WalletApiClient.postRequestObject(client, transactionInitialized.requestUri!!, walletMetadata, null)

            assertEquals(listOf("https://wallet.example"), requestObject.second.audience())
        }

    @Test
    fun `when wallet gets the request object, the JAR aud is the self-issued default`() =
        runTest {
            val initTransaction =
                VerifierApiClient
                    .loadInitTransactionTO("02-dcql.json")
                    .copy(jarMode = EmbedModeTO.ByReference, requestUriMethod = RequestUriMethodTO.Get)
            val transactionInitialized =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    VerifierApiClient.initTransaction(client, initTransaction),
                )

            val requestObject = WalletApiClient.getRequestObjectJsonResponse(client, transactionInitialized.requestUri!!)

            assertEquals(listOf("https://self-issued.me/v2"), requestObject.audience())
        }

    private fun JsonObjectBuilder.putValidWalletMetadata() {
        put(
            "vp_formats_supported",
            buildJsonObject {
                put("dc+sd-jwt", buildJsonObject {})
            },
        )
        put("response_types_supported", buildJsonArray { add("vp_token") })
        put("response_modes_supported", buildJsonArray { add("direct_post.jwt") })
    }

    private fun JsonObject.audience(): List<String>? =
        when (val aud = this["aud"]) {
            is JsonPrimitive -> listOf(aud.content)
            is JsonArray -> aud.map { it.jsonPrimitive.content }
            else -> null
        }
}
