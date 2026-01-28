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

import arrow.core.Either
import arrow.core.flatMap
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJackson
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.dropRootCAIfPresent
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.CreateJar
import com.nimbusds.oauth2.sdk.ResponseMode as NimbusResponseMode

/**
 * An implementation of [CreateJar] that uses Nimbus SDK
 */
class CreateJarNimbus : CreateJar {

    override fun invoke(
        verifierConfig: VerifierConfig,
        clock: Clock,
        presentation: Presentation.Requested,
        walletNonce: String?,
        walletJarEncryptionRequirement: EncryptionRequirement,
    ): Either<Throwable, Jwt> {
        val requestObject = requestObjectFromDomain(verifierConfig, clock, presentation)
        val signedJar = sign(verifierConfig.clientMetaData, presentation.responseMode, requestObject, walletNonce)
        return when (walletJarEncryptionRequirement) {
            EncryptionRequirement.NotRequired -> signedJar.map { it.serialize() }
            is EncryptionRequirement.Required -> signedJar.flatMap { encrypt(walletJarEncryptionRequirement, it) }.map { it.serialize() }
        }
    }

    internal fun sign(
        clientMetaData: ClientMetaData,
        responseMode: ResponseMode,
        requestObject: RequestObject,
        walletNonce: String?,
    ): Either<Throwable, SignedJWT> = Either.catch {
        val (key, algorithm) = requestObject.verifierId.jarSigning
        val header = JWSHeader.Builder(algorithm)
            .apply {
                when (requestObject.verifierId) {
                    is VerifierId.PreRegistered -> keyID(key.keyID)
                    is VerifierId.X509SanDns, is VerifierId.X509Hash -> x509CertChain(
                        key.parsedX509CertChain.dropRootCAIfPresent().map { Base64.encode(it.encoded) },
                    )
                }
            }
            .type(JOSEObjectType(RFC9101.REQUEST_OBJECT_MEDIA_SUBTYPE))
            .build()
        val claimSet = asClaimSet(toNimbus(clientMetaData, responseMode), requestObject, walletNonce)

        SignedJWT(header, claimSet).apply { sign(DefaultJWSSignerFactory().createJWSSigner(key, algorithm)) }
    }

    internal fun encrypt(
        walletJarEncryptionRequirement: EncryptionRequirement.Required,
        signed: SignedJWT,
    ): Either<Throwable, JWEObject> = Either.catch {
        val (walletJarEncryptionKey, encryptionAlgorithm, encryptionMethod) = walletJarEncryptionRequirement
        val encrypter = when (walletJarEncryptionKey) {
            is RSAKey -> RSAEncrypter(walletJarEncryptionKey)
            is ECKey -> ECDHEncrypter(walletJarEncryptionKey)
            is OctetKeyPair -> X25519Encrypter(walletJarEncryptionKey)
            else -> error("Unsupported JWK type '${walletJarEncryptionKey::javaClass.name}'")
        }

        val header = JWEHeader.Builder(encryptionAlgorithm, encryptionMethod)
            .contentType("JWT")
            .build()
        val payload = Payload(signed)

        JWEObject(header, payload).apply { encrypt(encrypter) }
    }

    /**
     * Maps a [RequestObject] into a Nimbus [JWTClaimsSet]
     */
    private fun asClaimSet(clientMetaData: OIDCClientMetadata?, r: RequestObject, walletNonce: String?): JWTClaimsSet {
        val responseType = ResponseType(*r.responseType.map { ResponseType.Value(it) }.toTypedArray())
        val clientId = ClientID(r.verifierId.clientId)
        val scope = Scope(*r.scope.map { Scope.Value(it) }.toTypedArray())
        val state = State(r.state)

        val authorizationRequestClaims = with(AuthorizationRequest.Builder(responseType, clientId)) {
            state(state)
            if (scope.isNotEmpty()) {
                scope(scope)
            }
            responseMode(NimbusResponseMode(r.responseMode))
            build()
        }.toJWTClaimsSet()

        return with(JWTClaimsSet.Builder(authorizationRequestClaims)) {
            fun optionalClaim(c: String, v: Any?) {
                v?.let { claim(c, it) }
            }
            issueTime(r.issuedAt.toJavaDate())
            audience(r.aud)
            claim(OpenId4VPSpec.NONCE, r.nonce)
            optionalClaim(OpenId4VPSpec.CLIENT_METADATA, clientMetaData?.toJSONObject())
            optionalClaim(OpenId4VPSpec.RESPONSE_URI, r.responseUri?.toExternalForm())
            optionalClaim(OpenId4VPSpec.DCQL_QUERY, r.dcqlQuery?.toJackson())
            optionalClaim(OpenId4VPSpec.TRANSACTION_DATA, r.transactionData?.toJackson())
            optionalClaim(OpenId4VPSpec.WALLET_NONCE, walletNonce)
            build()
        }
    }

    private fun toNimbus(
        c: ClientMetaData,
        responseMode: ResponseMode,
    ): OIDCClientMetadata {
        return OIDCClientMetadata().apply {
            if (responseMode is ResponseMode.DirectPostJwt) {
                jwkSet = JWKSet(listOf(responseMode.ephemeralResponseEncryptionKey)).toPublicJWKSet()
                setCustomField(
                    OpenId4VPSpec.ENCRYPTED_RESPONSE_ENC_VALUES_SUPPORTED,
                    c.responseEncryptionOption.encryptionMethods.map { it.name }.toList(),
                )
            }

            setCustomField(OpenId4VPSpec.VP_FORMATS_SUPPORTED, c.vpFormatsSupported.toJackson())
        }
    }
}
