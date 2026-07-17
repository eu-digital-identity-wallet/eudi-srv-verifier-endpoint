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

package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import arrow.core.nonEmptyListOf
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.TestUtils
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.domain.DCQL
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption
import eu.europa.ec.eudi.verifier.endpoint.domain.HashAlgorithm
import eu.europa.ec.eudi.verifier.endpoint.domain.HttpResponseModeOption
import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import eu.europa.ec.eudi.verifier.endpoint.domain.RegistrationCertificate
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestUriMethod
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseMode
import eu.europa.ec.eudi.verifier.endpoint.domain.UnresolvedAuthorizationRequestUri
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionTO
import kotlinx.serialization.json.Json
import net.minidev.json.JSONObject
import java.net.URL
import java.util.*
import kotlin.test.*
import kotlin.time.Duration.Companion.days

class CreateJarNimbusTest {
    private val verifier = TestContext.signedRequestObjectVerifier
    private val clientMetaData = TestContext.clientMetaData
    private val verifierId = TestContext.verifierId

    private val verifierConfig =
        VerifierConfig(
            verifierId = verifierId,
            requestJarOption = EmbedOption.ByValue,
            responseUriBuilder = { _ -> URL("https://foo") },
            defaultHttpResponseModeOption = HttpResponseModeOption.DirectPostJwt,
            maxAge = 3.days,
            clientMetaData = clientMetaData,
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

    private val createJar = CreateJarNimbus(verifierConfig)

    @Test
    fun `given a request object, it should be signed and decoded`() {
        val query = checkNotNull(Json.decodeFromString<InitTransactionTO>(TestUtils.loadResource("02-dcql.json")).dcqlQuery)
        val requestObject =
            RequestObject(
                verifierId = verifierId,
                responseType = listOf("vp_token"),
                query = query,
                scope = listOf("openid"),
                nonce = UUID.randomUUID().toString(),
                responseMode = "direct_post.jwt",
                responseUri = URL("https://foo"),
                state = TestContext.testRequestId.value,
                audience = emptyList(),
                issuedAt = TestContext.testClock.now(),
                verifierInfo = VerifierInfo("test", "test"),
            )

        // responseMode is direct_post.jwt, so we need to generate an ephemeral key
        val ecKey =
            ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.ECDH_ES)
                .keyID(UUID.randomUUID().toString())
                .generate()

        val jwt =
            createJar
                .sign(ResponseMode.OverHttp.DirectPostJwt(ecKey), requestObject, null)
                .serialize()
                .also { println(it) }
        val signedJwt = decode(jwt).getOrThrow().also { println(it) }
        assertX5cHeaderClaimDoesNotContainPEM(signedJwt.header)
        val claimSet = signedJwt.jwtClaimsSet
        assertEqualsRequestObjectJWTClaimSet(requestObject, claimSet)

        assertTrue { claimSet.claims.containsKey("client_metadata") }
        val clientMetadata = OIDCClientMetadata.parse(JSONObject(claimSet.getJSONObjectClaim("client_metadata")))
        assertNull(clientMetadata.jwkSetURI)
        assertEquals(JWKSet(ecKey).toPublicJWKSet(), clientMetadata.jwkSet)
    }

    private fun decode(jwt: String): Result<SignedJWT> =
        runCatching {
            val signedJWT = SignedJWT.parse(jwt)
            signedJWT.verify(verifier)
            signedJWT
        }

    private fun assertEqualsRequestObjectJWTClaimSet(
        r: RequestObject,
        c: JWTClaimsSet,
    ) {
        assertEquals(r.verifierId.clientId, c.getStringClaim("client_id"))
        assertEquals(r.responseType.joinToString(separator = " "), c.getStringClaim("response_type"))
        assertEquals(
            r.query,
            c
                .getJSONObjectClaim(OpenId4VPSpec.DCQL_QUERY)
                .toJsonObject()
                .decodeAs<DCQL>(),
        )
        assertEquals(r.scope.joinToString(separator = " "), c.getStringClaim("scope"))
        assertEquals(r.nonce, c.getStringClaim("nonce"))
        assertEquals(r.responseMode, c.getStringClaim("response_mode"))
        assertEquals(r.responseUri?.toExternalForm(), c.getStringClaim(OpenId4VPSpec.RESPONSE_URI))
        assertEquals(r.state, c.getStringClaim("state"))
    }

    private fun assertX5cHeaderClaimDoesNotContainPEM(header: JWSHeader) {
        val chain = assertNotNull(header.x509CertChain?.toNonEmptyListOrNull())
        chain.forEach {
            // Ensure it is not a base64 encoded PEM
            assertNull(X509CertUtils.parse(it.decodeToString()))

            // Ensure it is a base64 encoded DER
            assertNotNull(X509CertUtils.parse(it.decode()))
        }
    }
}
