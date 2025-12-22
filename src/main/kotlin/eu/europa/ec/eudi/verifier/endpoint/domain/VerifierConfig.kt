/*
 * Copyright (c) 2023 European Commission
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
@file:UseSerializers(JWSAlgorithmStringSerializer::class, NonEmptyListSerializer::class)

package eu.europa.ec.eudi.verifier.endpoint.domain

import arrow.core.Either
import arrow.core.Ior
import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.serialization.NonEmptyListSerializer
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.digest.hash
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.JWSAlgorithmStringSerializer
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.isSelfSigned
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import java.net.URL
import java.security.KeyStore
import java.security.cert.X509Certificate
import kotlin.time.Duration

typealias PresentationRelatedUrlBuilder<ID> = (ID) -> URL

/**
 * This is a configuration option for properties like JAR request/request_uri or
 * presentation_definition/presentation_definition_uri
 * where can be embedded either by value or by reference
 */
sealed interface EmbedOption<in ID> {
    data object ByValue : EmbedOption<Any>
    data class ByReference<ID>(val buildUrl: PresentationRelatedUrlBuilder<ID>) : EmbedOption<ID>

    companion object {
        fun <ID> byReference(urlBuilder: PresentationRelatedUrlBuilder<ID>): ByReference<ID> = ByReference(urlBuilder)
    }
}

/**
 * Configuration option for `request_uri_method`
 */
enum class RequestUriMethod {
    Get,
    Post,
}

/**
 * Configuration option for response mode
 */
enum class ResponseModeOption {
    DirectPost,
    DirectPostJwt,
}

sealed interface ResponseMode {

    data object DirectPost : ResponseMode

    data class DirectPostJwt(
        val ephemeralResponseEncryptionKey: JWK,
    ) : ResponseMode {
        init {
            require(ephemeralResponseEncryptionKey.isPrivate)
        }
    }
}

val ResponseMode.option: ResponseModeOption
    get() = when (this) {
        ResponseMode.DirectPost -> ResponseModeOption.DirectPost
        is ResponseMode.DirectPostJwt -> ResponseModeOption.DirectPostJwt
    }

data class ResponseEncryptionOption(
    val algorithm: JWEAlgorithm,
    val encryptionMethods: NonEmptyList<EncryptionMethod>,
) {
    init {
        require(algorithm in ECDHEncrypter.SUPPORTED_ALGORITHMS)
        require(ECDHEncrypter.SUPPORTED_ENCRYPTION_METHODS.containsAll(encryptionMethods))
    }
}

@Serializable
@JvmInline
value class CoseAlgorithm(val value: Int)

/**
 * Verifiable Presentation formats supported by Verifier Endpoint.
 */
@Serializable
data class VpFormatsSupported(
    @SerialName(OpenId4VPSpec.FORMAT_SD_JWT_VC) val sdJwtVc: SdJwtVc?,
    @SerialName(OpenId4VPSpec.FORMAT_MSO_MDOC) val msoMdoc: MsoMdoc?,
) {
    init {
        require(null != sdJwtVc || null != msoMdoc) {
            "At least one format must be specified."
        }
    }

    /**
     * SD-JWT VC
     */
    @Serializable
    data class SdJwtVc(
        @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTS_SD_JWT_VC_SD_JWT_ALGORITHMS)
        val sdJwtAlgorithms: NonEmptyList<JWSAlgorithm>?,

        @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTS_SD_JWT_VC_KB_JWT_ALGORITHMS)
        val kbJwtAlgorithms: NonEmptyList<JWSAlgorithm>?,
    ) {
        init {
            if (null != sdJwtAlgorithms) {
                require(sdJwtAlgorithms.all { it in JWSAlgorithm.Family.SIGNATURE }) {
                    "sdJwtAlgorithms must contain asymmetric signature algorithms"
                }
            }

            if (null != kbJwtAlgorithms) {
                require(kbJwtAlgorithms.all { it in JWSAlgorithm.Family.SIGNATURE }) {
                    "sdJwtAlgorithms must contain asymmetric signature algorithms"
                }
            }
        }
    }

    /**
     * MSO MDoc
     */
    @Serializable
    data class MsoMdoc(
        @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTED_MSO_MDOC_ISSUER_AUTH_ALGORITHMS)
        val issuerAuthAlgorithms: NonEmptyList<CoseAlgorithm>?,

        @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTED_MSO_MDOC_DEVICE_AUTH_ALGORITHMS)
        val deviceAuthAlgorithms: NonEmptyList<CoseAlgorithm>?,
    ) {
        companion object {
            val Default: MsoMdoc = MsoMdoc(
                issuerAuthAlgorithms = nonEmptyListOf(
                    CoseAlgorithm(-7), // AlgorithmID.ECDSA_256
                    CoseAlgorithm(-35), // AlgorithmID.ECDSA_384
                    CoseAlgorithm(-36), // AlgorithmID.ECDSA_512
                ),
                deviceAuthAlgorithms = nonEmptyListOf(
                    CoseAlgorithm(-7), // AlgorithmID.ECDSA_256
                    CoseAlgorithm(-35), // AlgorithmID.ECDSA_384
                    CoseAlgorithm(-36), // AlgorithmID.ECDSA_512
                ),
            )
        }
    }
}

/**
 * By OpenID Connect Dynamic Client Registration specification
 *
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html">OpenID Connect Dynamic Client Registration specification</a>
 */
data class ClientMetaData(
    val responseEncryptionOption: ResponseEncryptionOption,
    val vpFormatsSupported: VpFormatsSupported,
)

/**
 * Configuration options for signing.
 */
data class SigningConfig(
    val key: JWK,
    val algorithm: JWSAlgorithm,
) {
    init {
        require(key.isPrivate) { "a private key is required for signing" }
        require(!key.parsedX509CertChain.isNullOrEmpty()) { "signing key must contain a certificate chain" }
        require(!certificate.isSelfSigned()) { "signing key must not use a self-signed certificate" }
        require(algorithm in JWSAlgorithm.Family.SIGNATURE) { "'${algorithm.name}' is not a valid signature algorithm" }

        // Verify a JWSSigner can be instantiated with the provided key/algorithm combo
        Either.catch {
            DefaultJWSSignerFactory().createJWSSigner(key, algorithm)
        }.getOrThrow { IllegalArgumentException("Invalid configuration", it) }
    }

    /**
     * The signing [X509Certificate].
     */
    val certificate: X509Certificate
        get() = key.parsedX509CertChain.first()
}

typealias OriginalClientId = String
typealias ClientId = String

/**
 * Client Id (as defined by OpenId 4 VP) of the Verifier Endpoint.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme-an">https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme-an</a>
 */
sealed interface VerifierId {
    val originalClientId: OriginalClientId
    val jarSigning: SigningConfig
    val clientId: ClientId

    /**
     * This value represents the RFC6749 default behavior,
     * i.e., the Client Identifier needs to be known to the Wallet in advance of the Authorization Request
     * The Verifier's metadata is obtained using (RFC7591) or through out-of-band mechanisms.
     */
    data class PreRegistered(
        override val originalClientId: String,
        override val jarSigning: SigningConfig,
    ) : VerifierId {
        override val clientId: ClientId = originalClientId
    }

    /**
     * When the Client Identifier Prefix is x509_san_dns, the Client Identifier
     * MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    data class X509SanDns(
        override val originalClientId: String,
        override val jarSigning: SigningConfig,
    ) : VerifierId {
        init {
            require(jarSigning.certificate.containsSanDns(originalClientId)) {
                "Original Client Id '$originalClientId' not contained in 'DNS' Subject Alternative Names of JAR Signing Certificate."
            }
        }

        override val clientId: ClientId = "${OpenId4VPSpec.CLIENT_ID_PREFIX_X509_SAN_DNS}:$originalClientId"
    }

    /**
     * When the Client Identifier Prefix is x509_hash, the Client Identifier
     * MUST match the Base64 Url-Safe with no padding encoded SHA-256 hash of the DER
     * encoded leaf certificate
     */
    data class X509Hash(
        override val originalClientId: String,
        override val jarSigning: SigningConfig,
    ) : VerifierId {
        init {
            require(jarSigning.certificate.encodedHashMatches(originalClientId)) {
                "Original Client Id '$originalClientId' doesn't match the expected value"
            }
        }

        override val clientId: ClientId = "${OpenId4VPSpec.CLIENT_ID_PREFIX_X509_HASH}:$originalClientId"
    }
}

/**
 * Hashing algorithms.
 */
enum class HashAlgorithm(val ianaName: String) {
    SHA_256("sha-256"),
    SHA_384("sha-384"),
    SHA_512("sha-512"),
    SHA3_224("sha3-224"),
    SHA3_256("sha3-256"),
    SHA3_384("sha3-384"),
    SHA3_512("sha3-512"),
}

/**
 * Verifier configuration options
 */
data class VerifierConfig(
    val verifierId: VerifierId,
    val requestJarOption: EmbedOption<RequestId>,
    val requestUriMethod: RequestUriMethod,
    val responseModeOption: ResponseModeOption,
    val responseUriBuilder: PresentationRelatedUrlBuilder<RequestId>,
    val maxAge: Duration,
    val clientMetaData: ClientMetaData,
    val transactionDataHashAlgorithm: HashAlgorithm,
    val authorizationRequestUri: UnresolvedAuthorizationRequestUri,
    val trustSourcesConfig: Map<Regex, TrustSourceConfig>?,
)

/**
 * Checks if [value] is a Subject Alternative Name of [type] in this [X509Certificate].
 */
private fun X509Certificate.containsSan(value: String, type: SanType) =
    value in this.san(type)

/**
 * Checks if [value] is a 'DNS' Subject Alternative Name in this [X509Certificate].
 */
private fun X509Certificate.containsSanDns(value: String) =
    containsSan(value, SanType.DNS)

private fun X509Certificate.encodedHashMatches(expected: String): Boolean {
    val hash = hash(encoded, HashAlgorithm.SHA_256)
    val encodedHash = base64UrlNoPadding.encode(hash)
    return expected == encodedHash
}

/**
 * Checks if [value] is a 'URI' Subject Alternative Name in this [X509Certificate].
 */
private fun X509Certificate.containsSanUri(value: String) =
    containsSan(value, SanType.URI)

/**
 * Gets the Subject Alternative Names of the provided [type] from this [X509Certificate].
 */
private fun X509Certificate.san(type: SanType) =
    buildList {
        subjectAlternativeNames
            ?.filter { subjectAltNames -> !subjectAltNames.isNullOrEmpty() && subjectAltNames.size == 2 }
            ?.forEach { entry ->
                val altNameType = entry[0] as Int
                entry[1]?.takeIf { altNameType == type.asInt() }?.let { add(it as String) }
            }
    }

/**
 * Types of Subject Alternative Names.
 */
private enum class SanType {
    URI,
    DNS,
}

/**
 * Gets the numeric value of this [SanType].
 *
 * See also https://www.rfc-editor.org/rfc/rfc5280.html
 *
 */
private fun SanType.asInt() =
    when (this) {
        SanType.URI -> 6
        SanType.DNS -> 2
    }

typealias TrustSourceConfig = Ior<TrustedListConfig, KeyStoreConfig>

enum class ProviderKind(val value: String) {
    PIDProvider("http://uri.etsi.org/Svc/Svctype/Provider/PID"),
    QEEAProvider("http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"),
    PubEAAProvider("http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA"),
}

data class TrustedListConfig(
    val location: URL,
    val serviceTypeFilter: ProviderKind?,
    val refreshInterval: String = "0 0 * * * *",
    val keystoreConfig: KeyStoreConfig?,
)

data class KeyStoreConfig(
    val keystorePath: String,
    val keystoreType: String? = "JKS",
    val keystorePassword: String? = "",
    val keystore: KeyStore,
)

internal fun VpFormatsSupported.supports(format: Format): Boolean =
    when (format) {
        Format.SdJwtVc -> null != sdJwtVc
        Format.MsoMdoc -> null != msoMdoc
        else -> false
    }

fun TrustSourcesConfig(trustedList: TrustedListConfig?, keystore: KeyStoreConfig?): Ior<TrustedListConfig, KeyStoreConfig> =
    Ior.fromNullables(trustedList, keystore) ?: error("Either trustedList or keystore must be provided")
