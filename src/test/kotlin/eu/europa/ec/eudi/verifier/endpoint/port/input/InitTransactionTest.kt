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
@file:Suppress("invisible_reference", "invisible_member")

package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.getOrElse
import arrow.core.left
import arrow.core.nonEmptyListOf
import arrow.core.raise.either
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.*
import java.net.URL
import kotlin.test.*
import kotlin.time.Duration.Companion.days

class InitTransactionTest {
    private val testTransactionId = TestContext.testTransactionId

    private val uri = URL("https://foo")
    private val verifierConfig =
        VerifierConfig(
            verifierId = TestContext.verifierId,
            requestJarOption = EmbedOption.ByValue,
            responseUriBuilder = { _ -> uri },
            defaultHttpResponseModeOption = HttpResponseModeOption.DirectPostJwt,
            maxAge = 3.days,
            clientMetaData = TestContext.clientMetaData,
            transactionDataHashAlgorithm = HashAlgorithm.SHA_256,
            requestUriMethod = RequestUriMethod.Get,
            authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri("haip-vp://").getOrThrow(),
            registrationCertificates =
                listOf(
                    RegistrationCertificate.create(
                        description = "test",
                        registrationCertificate =
                            "eyJ4NWMiOlsiTUlJQkhEQ0J4S0FEQWdFQ0FoUmp6T3Z1VUNXNFVieXMyNWgvRndHZlN4SFR1a" +
                                "kFLQmdncWhrak9QUVFEQWpBUE1RMHdDd1lEVlFRRERBUjBaWE4wTUI0WERUSTJNRGN4TURBNE1EZ3dOMW9YRFRJM01E" +
                                "Y3hNREE0TURnd04xb3dEekVOTUFzR0ExVUVBd3dFZEdWemREQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTB" +
                                "JQUJKZlY0dFJ5U1dybTdsVkFTQjk0bUJLTTR3dlBKRkV1S012VWhwcUlyY3JkMkduam1PejJJS3Vrb0tkZVRjbTkzcz" +
                                "M5U2w1NHl4UTI0Q3NLTVlmM2t3c3dDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdhdFJ6eUVidklLWk9wNVlyUDlJYW5Sc" +
                                "VcyRTk1dC9vM3F1cmV0OXVXY2hrQ0lIcndEQ3dwQlJKNk9LQUNrZmNGRVZvWmNiTTU4NGZpRjVzb2h1TXNLcjg3Il0s" +
                                "InR5cCI6InJjLXdycCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJuYW1lIjoiS290bGluIElzc3VlciBTaWduZXIgRGV2Ii" +
                                "wic3ViX2xuIjoiTmlzY3kiLCJzdWIiOiJMRUlFVS0xMjM0NTY3ODkiLCJjb3VudHJ5IjoiRVUiLCJyZWdpc3RyeV91c" +
                                "mkiOiJodHRwczovL3JlZ2lzdHJ5LmV4YW1wbGUuZXUiLCJzcnZfZGVzY3JpcHRpb24iOlt7ImxhbmciOiJlbiIsInZh" +
                                "bHVlIjoiQW4gaW1wbGVtZW50YXRpb24gb2YgYSBjcmVkZW50aWFsIGlzc3Vpbmcgc2VydmljZSwgYWNjb3JkaW5nIHR" +
                                "vIE9wZW5JZDRWQ0kgLSB2MS4wIn1dLCJlbnRpdGxlbWVudHMiOlsiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW" +
                                "50aXRsZW1lbnQvUElEX1Byb3ZpZGVyIiwiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW50aXRsZW1lbnQvUUVBQ" +
                                "V9Qcm92aWRlciIsImh0dHBzOi8vdXJpLmV0c2kub3JnLzE5NDc1L0VudGl0bGVtZW50L1BVQl9FQUFfUHJvdmlkZXIi" +
                                "XSwicHJpdmFjeV9wb2xpY3kiOiJodHRwczovL2Rldi5pc3N1ZXItYmFja2VuZC5ldWRpdy5kZXYvcHJpdmFjeSIsIml" +
                                "uZm9fdXJpIjoiaHR0cHM6Ly9kZXYuaXNzdWVyLWJhY2tlbmQuZXVkaXcuZGV2Iiwic3VwcG9ydF91cmkiOiJodHRwcz" +
                                "ovL2Rldi5rb3RsaW5Jc3N1ZXJTaWduZXIuY29tL3N1cHBvcnQiLCJzdXBlcnZpc29yeV9hdXRob3JpdHkiOnsiZW1ha" +
                                "WwiOiJzdXBlcnZpc29yeUBhdXRob3JpdHkuZXhhbXBsZS5ldSIsInBob25lIjoiKzQ5MzAxMjM0NTY3IiwidXJpIjoi" +
                                "aHR0cHM6Ly9zdXBlcnZpc29yeS5hdXRob3JpdHkuZXhhbXBsZS5ldSJ9LCJwb2xpY3lfaWQiOlsiMC40LjAuMTk0NzU" +
                                "uMy4xIl0sImNlcnRpZmljYXRlX3BvbGljeSI6Imh0dHBzOi8vZXhhbXBsZS5ldS9jZXJ0aWZpY2F0ZS1wb2xpY3kiLC" +
                                "JpYXQiOjE3ODM2ODEwMjgsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJpZHgiOjkxMCwidXJpIjoiaHR0cHM6Ly9pc" +
                                "3N1ZXIuZXVkaXcuZGV2L3Rva2VuX3N0YXR1c19saXN0L0VVL2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xLzIwZWY5ZTk4" +
                                "LTg2NzYtNDViYy04OWJhLTE3MDhmMGYyMTIzOSJ9fSwicHJvdmlkZXNfYXR0ZXN0YXRpb25zIjpbeyJmb3JtYXQiOiJ" +
                                "kYytzZC1qd3QiLCJtZXRhIjp7InZjdF92YWx1ZXMiOlsidXJuOmV1ZGk6cGlkOjEiLCJ1cm46ZXUuZXVyb3BhLmVjLm" +
                                "V1ZGk6bGVhcm5pbmc6Y3JlZGVudGlhbDoxIl19fSx7ImZvcm1hdCI6Im1zb19tZG9jIiwibWV0YSI6eyJkb2N0eXBlX" +
                                "3ZhbHVlIjoiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEifX0seyJmb3JtYXQiOiJtc29fbWRvYyIsIm1ldGEiOnsiZG9j" +
                                "dHlwZV92YWx1ZSI6Im9yZy5pc28uMTgwMTMuNS4xLm1ETCJ9fV19.h3wtRbSVXVGJVblxwHLQQivFN-iQiyyIGLmbFo" +
                                "NHpC8GRcKjuseUhbatzS-PGh7eDBPOCwh0VSgotEtjTiYKzA",
                        intentUseId = "1",
                    ),
                ),
        )

    @Test
    fun `when request option is embed by value, request should be present and presentation should be RequestObjectRetrieved`() =
        runTest {
            val input =
                InitTransactionTO(
                    dcqlQuery(),
                    "nonce",
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val jwtSecuredAuthorizationRequest =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            assertTrue {
                loadPresentationById(testTransactionId)?.let { it is Presentation.RequestObjectRetrieved } ?: false
            }
        }

    @Test
    fun `when request option is embed by ref, request_uri should be present and presentation should be Requested`() =
        runTest {
            val uri = URL("https://foo")
            val verifierConfig =
                VerifierConfig(
                    verifierId = TestContext.verifierId,
                    requestJarOption = EmbedOption.ByReference { _ -> uri },
                    responseUriBuilder = { _ -> URL("https://foo") },
                    defaultHttpResponseModeOption = HttpResponseModeOption.DirectPostJwt,
                    maxAge = 3.days,
                    clientMetaData = TestContext.clientMetaData,
                    transactionDataHashAlgorithm = HashAlgorithm.SHA_256,
                    requestUriMethod = RequestUriMethod.Get,
                    authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri("haip-vp://").getOrThrow(),
                    registrationCertificates =
                        listOf(
                            RegistrationCertificate.create(
                                description = "test",
                                registrationCertificate =
                                    "eyJ4NWMiOlsiTUlJQkhEQ0J4S0FEQWdFQ0FoUmp6T3Z1VUNXNFVieXMyNWgvRndHZlN4SFR1a" +
                                        "kFLQmdncWhrak9QUVFEQWpBUE1RMHdDd1lEVlFRRERBUjBaWE4wTUI0WERUSTJNRGN4TURBNE1EZ3dOMW9YRFRJM01E" +
                                        "Y3hNREE0TURnd04xb3dEekVOTUFzR0ExVUVBd3dFZEdWemREQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTB" +
                                        "JQUJKZlY0dFJ5U1dybTdsVkFTQjk0bUJLTTR3dlBKRkV1S012VWhwcUlyY3JkMkduam1PejJJS3Vrb0tkZVRjbTkzcz" +
                                        "M5U2w1NHl4UTI0Q3NLTVlmM2t3c3dDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdhdFJ6eUVidklLWk9wNVlyUDlJYW5Sc" +
                                        "VcyRTk1dC9vM3F1cmV0OXVXY2hrQ0lIcndEQ3dwQlJKNk9LQUNrZmNGRVZvWmNiTTU4NGZpRjVzb2h1TXNLcjg3Il0s" +
                                        "InR5cCI6InJjLXdycCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJuYW1lIjoiS290bGluIElzc3VlciBTaWduZXIgRGV2Ii" +
                                        "wic3ViX2xuIjoiTmlzY3kiLCJzdWIiOiJMRUlFVS0xMjM0NTY3ODkiLCJjb3VudHJ5IjoiRVUiLCJyZWdpc3RyeV91c" +
                                        "mkiOiJodHRwczovL3JlZ2lzdHJ5LmV4YW1wbGUuZXUiLCJzcnZfZGVzY3JpcHRpb24iOlt7ImxhbmciOiJlbiIsInZh" +
                                        "bHVlIjoiQW4gaW1wbGVtZW50YXRpb24gb2YgYSBjcmVkZW50aWFsIGlzc3Vpbmcgc2VydmljZSwgYWNjb3JkaW5nIHR" +
                                        "vIE9wZW5JZDRWQ0kgLSB2MS4wIn1dLCJlbnRpdGxlbWVudHMiOlsiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW" +
                                        "50aXRsZW1lbnQvUElEX1Byb3ZpZGVyIiwiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW50aXRsZW1lbnQvUUVBQ" +
                                        "V9Qcm92aWRlciIsImh0dHBzOi8vdXJpLmV0c2kub3JnLzE5NDc1L0VudGl0bGVtZW50L1BVQl9FQUFfUHJvdmlkZXIi" +
                                        "XSwicHJpdmFjeV9wb2xpY3kiOiJodHRwczovL2Rldi5pc3N1ZXItYmFja2VuZC5ldWRpdy5kZXYvcHJpdmFjeSIsIml" +
                                        "uZm9fdXJpIjoiaHR0cHM6Ly9kZXYuaXNzdWVyLWJhY2tlbmQuZXVkaXcuZGV2Iiwic3VwcG9ydF91cmkiOiJodHRwcz" +
                                        "ovL2Rldi5rb3RsaW5Jc3N1ZXJTaWduZXIuY29tL3N1cHBvcnQiLCJzdXBlcnZpc29yeV9hdXRob3JpdHkiOnsiZW1ha" +
                                        "WwiOiJzdXBlcnZpc29yeUBhdXRob3JpdHkuZXhhbXBsZS5ldSIsInBob25lIjoiKzQ5MzAxMjM0NTY3IiwidXJpIjoi" +
                                        "aHR0cHM6Ly9zdXBlcnZpc29yeS5hdXRob3JpdHkuZXhhbXBsZS5ldSJ9LCJwb2xpY3lfaWQiOlsiMC40LjAuMTk0NzU" +
                                        "uMy4xIl0sImNlcnRpZmljYXRlX3BvbGljeSI6Imh0dHBzOi8vZXhhbXBsZS5ldS9jZXJ0aWZpY2F0ZS1wb2xpY3kiLC" +
                                        "JpYXQiOjE3ODM2ODEwMjgsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJpZHgiOjkxMCwidXJpIjoiaHR0cHM6Ly9pc" +
                                        "3N1ZXIuZXVkaXcuZGV2L3Rva2VuX3N0YXR1c19saXN0L0VVL2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xLzIwZWY5ZTk4" +
                                        "LTg2NzYtNDViYy04OWJhLTE3MDhmMGYyMTIzOSJ9fSwicHJvdmlkZXNfYXR0ZXN0YXRpb25zIjpbeyJmb3JtYXQiOiJ" +
                                        "kYytzZC1qd3QiLCJtZXRhIjp7InZjdF92YWx1ZXMiOlsidXJuOmV1ZGk6cGlkOjEiLCJ1cm46ZXUuZXVyb3BhLmVjLm" +
                                        "V1ZGk6bGVhcm5pbmc6Y3JlZGVudGlhbDoxIl19fSx7ImZvcm1hdCI6Im1zb19tZG9jIiwibWV0YSI6eyJkb2N0eXBlX" +
                                        "3ZhbHVlIjoiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEifX0seyJmb3JtYXQiOiJtc29fbWRvYyIsIm1ldGEiOnsiZG9j" +
                                        "dHlwZV92YWx1ZSI6Im9yZy5pc28uMTgwMTMuNS4xLm1ETCJ9fV19.h3wtRbSVXVGJVblxwHLQQivFN-iQiyyIGLmbFo" +
                                        "NHpC8GRcKjuseUhbatzS-PGh7eDBPOCwh0VSgotEtjTiYKzA",
                                intentUseId = "1",
                            ),
                        ),
                )

            val input =
                InitTransactionTO(
                    dcqlQuery(),
                    nonce = "nonce",
                    intendedUseId = "1",
                )

            val useCase =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val jwtSecuredAuthorizationRequest =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertEquals(uri.toExternalForm(), jwtSecuredAuthorizationRequest.requestUri)
            assertTrue {
                loadPresentationById(testTransactionId)?.let { it is Presentation.Requested } ?: false
            }
        }

    @Test
    fun `when input misses DCQL validation error is raised`() =
        runTest {
            // Input is invalid.
            //  Misses DCQL
            val input =
                InitTransactionTO(
                    dcqlQuery = null,
                    nonce = "nonce",
                    intendedUseId = "1",
                )
            testWithInvalidInput(input, ValidationError.MissingPresentationQuery)
        }

    @Test
    fun `when input misses nonce validation error is raised`() =
        runTest {
            // Input is invalid.
            val input =
                InitTransactionTO(
                    dcqlQuery(),
                    nonce = null,
                    intendedUseId = "1",
                )
            testWithInvalidInput(input, ValidationError.MissingNonce)
        }

    /**
     * Verifies [InitTransactionTO.responseMode] takes precedence over [VerifierConfig.defaultHttpResponseModeOption].
     */
    @Test
    fun `when response_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
            val input =
                InitTransactionTO(
                    dcqlQuery(),
                    nonce = "nonce",
                    responseMode = InitTransactionTO.ResponseModeTO.DirectPost,
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val jwtSecuredAuthorizationRequest =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            val presentation = loadPresentationById(testTransactionId)
            val requestObjectRetrieved = assertIs<Presentation.RequestObjectRetrieved>(presentation)
            assertEquals(ResponseModeType.DirectPost, requestObjectRetrieved.channel.responseMode.type)
        }

    /**
     * Verifies [InitTransactionTO.jarMode] takes precedence over [VerifierConfig.requestJarOption].
     */
    @Test
    fun `when jar_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
            val input =
                InitTransactionTO(
                    dcqlQuery = dcqlQuery(),
                    nonce = "nonce",
                    jarMode = EmbedModeTO.ByReference,
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            // we expect the Authorization Request to contain a request_uri
            // and the Presentation to be in state Requested
            val jwtSecuredAuthorizationRequest =
                assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                    either { useCase(input) }.getOrElse { fail("Unexpected $it") },
                )
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNull(jwtSecuredAuthorizationRequest.request)
            assertNotNull(jwtSecuredAuthorizationRequest.requestUri)
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.Requested>(presentation)
        }

    @Test
    fun `when wallet_response_redirect_uri_template is invalid, validation error InvalidWalletResponseTemplate should be raised`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            val invalidPlaceHolderInput =
                InitTransactionTO(
                    dcqlQuery = dcqlQuery(),
                    "nonce",
                    redirectUriTemplate = "https://client.example.org/cb#response_code=#CODE#",
                    intendedUseId = "1",
                )

            either { useCase(invalidPlaceHolderInput) }
                .onLeft {
                    assertTrue(
                        "Should fail with ValidationError.InvalidWalletResponseTemplate",
                    ) { it == ValidationError.InvalidWalletResponseTemplate }
                }.onRight {
                    fail("Should fail with ValidationError.InvalidWalletResponseTemplate")
                }

            val invalidUrlInput =
                InitTransactionTO(
                    dcqlQuery = dcqlQuery(),
                    "nonce",
                    redirectUriTemplate =
                        "hts:/client.example.org/cb%response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
                    intendedUseId = "1",
                )

            either { useCase(invalidUrlInput) }
                .onLeft {
                    assertTrue(
                        "Should fail with ValidationError.InvalidWalletResponseTemplate",
                    ) { it == ValidationError.InvalidWalletResponseTemplate }
                }.onRight {
                    fail("Should fail with ValidationError.InvalidWalletResponseTemplate")
                }
        }

    @Test
    fun `when wallet_response_redirect_uri_template is valid, then get wallet response method should be REDIRECT`() =
        runTest {
            val input =
                InitTransactionTO(
                    dcqlQuery(),
                    "nonce",
                    redirectUriTemplate =
                        "https://client.example.org/cb#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                either { useCase(input) }.getOrElse { fail("Unexpected $it") },
            )
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.RequestObjectRetrieved>(presentation)
            assertIs<Channel.OverHttp>(presentation.channel)
            assertIs<GetWalletResponseMethod.Redirect>(presentation.channel.getWalletResponseMethod)
        }

    @Test
    fun `when wallet_response_redirect_uri_template is not passed, then get wallet response method should be POLL`() =
        runTest {
            val input =
                InitTransactionTO(
                    dcqlQuery(),
                    "nonce",
                    intendedUseId = "1",
                )

            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(
                either { useCase(input) }.getOrElse { fail("Unexpected $it") },
            )
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.RequestObjectRetrieved>(presentation)
            assertIs<Channel.OverHttp>(presentation.channel)
            assertIs<GetWalletResponseMethod.Poll>(presentation.channel.getWalletResponseMethod)
        }

    @Test
    fun `when transaction_data contains jsonobjects without required properties, inittransaction fails`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            suspend fun test(transactionData: JsonObject) {
                val input =
                    VerifierApiClient
                        .loadInitTransactionTO(
                            "00-dcql.json",
                        ).copy(transactionData = listOf(transactionData))

                val result = either { useCase(input) }
                assertEquals(ValidationError.InvalidTransactionData.left(), result)
            }

            val withoutType = JsonObject(emptyMap())
            val withoutCredentialIds =
                buildJsonObject {
                    put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "foo.bar")
                }

            test(withoutType)
            test(withoutCredentialIds)
        }

    @Test
    fun `when transaction_data contains jsonobjects with invalid credential ids, inittransaction fails`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            suspend fun test(
                baseInput: String,
                credentialId: String,
            ) {
                val transactionData =
                    buildJsonObject {
                        put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "foo.bar")
                        putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                            add(credentialId)
                        }
                    }

                val input =
                    VerifierApiClient
                        .loadInitTransactionTO(
                            baseInput,
                        ).copy(transactionData = listOf(transactionData))

                val result = either { useCase(input) }.leftOrNull()
                assertEquals(ValidationError.InvalidTransactionData, result)
            }

            test("00-dcql.json", "_foo_wa_driver_license")
            test("04-dcql.json", "_foo_employment_input")
        }

    @Test
    fun `when transaction_data contains jsonobjects with valid credential ids, inittransaction succeeds`() =
        runTest {
            val useCase: InitTransaction =
                TestContext.initTransaction(
                    verifierConfig,
                    EmbedOption.byReference { _ -> uri },
                )

            suspend fun test(
                baseInput: String,
                credentialId: String,
            ) {
                val transactionData =
                    buildJsonObject {
                        put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "foo.bar")
                        putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                            add(credentialId)
                        }
                    }

                val input =
                    VerifierApiClient
                        .loadInitTransactionTO(
                            baseInput,
                        ).copy(transactionData = listOf(transactionData))

                val result = either { useCase(input) }
                val response =
                    assertNotNull(assertIs<InitTransactionResponse.JwtSecuredAuthorizationRequestTO>(result.getOrNull()))
                val jar =
                    assertNotNull(response.request).let {
                        SignedJWT.parse(it).jwtClaimsSet
                    }
                val jarTransactionData =
                    run {
                        val jarTransactionDataList =
                            assertNotNull(jar.getStringListClaim(OpenId4VPSpec.TRANSACTION_DATA))
                        assertEquals(1, jarTransactionDataList.size)
                        val encodedJarTransactionData = jarTransactionDataList.first()
                        val decodedJarTransactionData = base64UrlNoPadding.decodeToByteString(encodedJarTransactionData)
                        Json.decodeFromString<JsonObject>(decodedJarTransactionData.decodeToString())
                    }
                val expectedJarTransactionData =
                    run {
                        val hashAlgorithms =
                            buildJsonArray {
                                add(verifierConfig.transactionDataHashAlgorithm.ianaName)
                            }
                        JsonObject(transactionData + (OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS to hashAlgorithms))
                    }
                assertEquals(expectedJarTransactionData, jarTransactionData)
            }

            test("00-dcql.json", "wa_driver_license")
            test("04-dcql.json", "employment_input")
        }

    private fun testWithInvalidInput(
        input: InitTransactionTO,
        expectedError: ValidationError,
    ) = either {
        context(verifierConfig.transactionDataHashAlgorithm, verifierConfig.clientMetaData.vpFormatsSupported) {
            validate(
                input.dcqlQuery,
                input.nonce,
                input.transactionData,
            )
        }
    }.fold(
        ifRight = { fail("Invalid input accepted") },
        ifLeft = { error -> assertEquals(expectedError, error) },
    )

    private suspend fun loadPresentationById(id: TransactionId) = TestContext.loadPresentationById(id)

    private fun dcqlQuery() = VerifierApiClient.loadInitTransactionTO("00-dcql.json").dcqlQuery!!
}
