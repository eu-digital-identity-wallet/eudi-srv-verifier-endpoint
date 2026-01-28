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
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.DCQL
import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseMode
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionTO
import kotlinx.serialization.json.Json
import net.minidev.json.JSONObject
import java.net.URL
import java.util.*
import kotlin.test.*

class CreateJarNimbusTest {

    private val createJar = TestContext.createJar
    private val verifier = TestContext.signedRequestObjectVerifier
    private val clientMetaData = TestContext.clientMetaData
    private val verifierId = TestContext.verifierId

    @Test
    fun `given a request object, it should be signed and decoded`() {
        val query = Json.decodeFromString<InitTransactionTO>(TestUtils.loadResource("02-dcql.json")).dcqlQuery
        val requestObject = RequestObject(
            verifierId = verifierId,
            responseType = listOf("vp_token"),
            dcqlQuery = query,
            scope = listOf("openid"),
            nonce = UUID.randomUUID().toString(),
            responseMode = "direct_post.jwt",
            responseUri = URL("https://foo"),
            state = TestContext.testRequestId.value,
            aud = emptyList(),
            issuedAt = TestContext.testClock.now(),
        )

        // responseMode is direct_post.jwt, so we need to generate an ephemeral key
        val ecKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID(UUID.randomUUID().toString())
            .generate()

        val jwt = createJar.sign(clientMetaData, ResponseMode.DirectPostJwt(ecKey), requestObject, null)
            .getOrThrow()
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

    private fun decode(jwt: String): Result<SignedJWT> {
        return runCatching {
            val signedJWT = SignedJWT.parse(jwt)
            signedJWT.verify(verifier)
            signedJWT
        }
    }

    private fun assertEqualsRequestObjectJWTClaimSet(r: RequestObject, c: JWTClaimsSet) {
        assertEquals(r.verifierId.clientId, c.getStringClaim("client_id"))
        assertEquals(r.responseType.joinToString(separator = " "), c.getStringClaim("response_type"))
        assertEquals(
            r.dcqlQuery,
            c.getJSONObjectClaim(OpenId4VPSpec.DCQL_QUERY).toJsonObject().decodeAs<DCQL>().getOrThrow(),
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
