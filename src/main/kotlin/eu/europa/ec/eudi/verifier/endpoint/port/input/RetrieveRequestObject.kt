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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.raise.Raise
import arrow.core.raise.context.bind
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import arrow.core.raise.effect
import arrow.core.raise.recover
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.CreateJar
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.reflect.KClass

/**
 * Method used to invoke GetRequestObject.
 */
sealed interface RetrieveRequestObjectMethod {
    data object Get : RetrieveRequestObjectMethod

    data class Post(
        val walletMetadata: String?,
        val walletNonce: String?,
    ) : RetrieveRequestObjectMethod
}

/**
 * Errors that can be produced by GetRequestObject
 */
sealed interface RetrieveRequestObjectError {
    data object PresentationNotFound : RetrieveRequestObjectError

    data class InvalidState(
        val expected: KClass<out Presentation>,
        val actual: KClass<out Presentation>,
    ) : RetrieveRequestObjectError

    data class InvalidRequestUriMethod(
        val expected: RequestUriMethod,
    ) : RetrieveRequestObjectError

    data class UnparsableWalletMetadata(
        val message: String,
        val cause: Throwable? = null,
    ) : RetrieveRequestObjectError

    data class UnsupportedWalletMetadata(
        val message: String,
        val cause: Throwable? = null,
    ) : RetrieveRequestObjectError

    data class InvalidWalletMetadata(
        val message: String,
        val cause: Throwable? = null,
    ) : RetrieveRequestObjectError
}

/**
 * Given a [RequestId] it returns a RFC9101 Request Object
 * encoded as JWT, if the [Presentation] is input state [Presentation.Requested].
 * In this case, the [Presentation] is updated to [Presentation.RequestObjectRetrieved]
 * input order to guarantee that only once the Request Object can be retrieved by
 * the wallet
 */
fun interface RetrieveRequestObject {
    context(_: Raise<RetrieveRequestObjectError>)
    suspend operator fun invoke(
        requestId: RequestId,
        method: RetrieveRequestObjectMethod,
    ): Jwt
}

class RetrieveRequestObjectLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val createJar: CreateJar,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) : RetrieveRequestObject {
    private val walletMetadataValidator = WalletMetadataValidator(verifierConfig)

    context(_: Raise<RetrieveRequestObjectError>)
    override suspend operator fun invoke(
        requestId: RequestId,
        method: RetrieveRequestObjectMethod,
    ): Jwt =
        when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> {
                raise(RetrieveRequestObjectError.PresentationNotFound)
            }

            else -> {
                effect {
                    found(presentation, method)
                }.recover { error ->
                    publishError(presentation, error)
                    raise(error)
                }.bind()
            }
        }

    private suspend fun publishError(
        presentation: Presentation,
        error: RetrieveRequestObjectError,
    ) {
        causeOf(error)?.let { cause ->
            val event = PresentationEvent.FailedToRetrieveRequestObject(presentation.id, clock.now(), cause)
            publishPresentationEvent(event)
        }
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private suspend fun found(
        presentation: Presentation,
        method: RetrieveRequestObjectMethod,
    ): Jwt {
        ensure(presentation is Presentation.Requested) {
            RetrieveRequestObjectError.InvalidState(Presentation.Requested::class, presentation::class)
        }

        check(presentation.channel is Channel.OverHttp)

        suspend fun updatePresentationAndCreateJar(
            encryptionRequirement: EncryptionRequirement,
        ): Pair<Presentation.RequestObjectRetrieved, Jwt> {
            val jar =
                createJar(presentation, method.walletNonceOrNull, encryptionRequirement)
            val updatedPresentation = presentation.retrieveRequestObject(clock)
            storePresentation(updatedPresentation)
            return updatedPresentation to jar
        }

        suspend fun log(
            p: Presentation.RequestObjectRetrieved,
            jwt: Jwt,
        ) {
            val event = PresentationEvent.RequestObjectRetrieved(p.id, p.requestObjectRetrievedAt, jwt)
            publishPresentationEvent(event)
        }

        when (method) {
            is RetrieveRequestObjectMethod.Get -> {
                ensure(
                    presentation.channel.requestUriMethod == RequestUriMethod.PostOrGet ||
                        presentation.channel.requestUriMethod == RequestUriMethod.Get,
                ) {
                    RetrieveRequestObjectError.InvalidRequestUriMethod(presentation.channel.requestUriMethod)
                }
            }

            is RetrieveRequestObjectMethod.Post -> {
                ensure(
                    presentation.channel.requestUriMethod == RequestUriMethod.PostOrGet ||
                        presentation.channel.requestUriMethod == RequestUriMethod.Post,
                ) {
                    RetrieveRequestObjectError.InvalidRequestUriMethod(presentation.channel.requestUriMethod)
                }
            }
        }

        val walletMetadata = method.walletMetadataOrNull?.let { parseWalletMetadata(it) }
        val encryptionRequirement =
            walletMetadata?.validate(presentation) ?: EncryptionRequirement.NotRequired

        val (updatePresentation, jar) = updatePresentationAndCreateJar(encryptionRequirement)
        log(updatePresentation, jar)
        return jar
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private fun WalletMetadataTO.validate(presentation: Presentation.Requested): EncryptionRequirement =
        walletMetadataValidator.validate(this, presentation)
}

/**
 * Validator for Wallet Metadata.
 */
private class WalletMetadataValidator(
    private val verifierConfig: VerifierConfig,
) {
    context(_: Raise<RetrieveRequestObjectError>)
    fun validate(
        metadata: WalletMetadataTO,
        presentation: Presentation.Requested,
    ): EncryptionRequirement {
        ensureWalletSupportsRequiredVpFormats(metadata, presentation)
        ensureWalletSupportsVerifierClientIdPrefix(metadata)
        ensureVerifierSupportsWalletJarSigningAlgorithms(metadata)
        ensureWalletSupportsRequiredResponseType(metadata)
        ensureWalletSupportsRequiredResponseMode(metadata, presentation)
        return encryptionRequirement(metadata)
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private fun ensureWalletSupportsRequiredVpFormats(
        metadata: WalletMetadataTO,
        presentation: Presentation.Requested,
    ) {
        val walletSupportedVpFormats = metadata.vpFormatsSupported
        val queryRequiredFormats =
            presentation.query.credentials.value
                .map { it.format }
                .toSet()

        val verifierSupportedVpFormats = verifierConfig.clientMetaData.vpFormatsSupported
        val walletSupportsAllRequiredVpFormats =
            queryRequiredFormats
                .map { requiredFormat ->
                    when (requiredFormat) {
                        Format.SdJwtVc -> {
                            val verifierSupported = checkNotNull(verifierSupportedVpFormats.sdJwtVc)
                            val walletSupported = walletSupportedVpFormats.sdJwtVc
                            null != walletSupported && commonGround(walletSupported, verifierSupported)
                        }

                        Format.MsoMdoc -> {
                            checkNotNull(verifierSupportedVpFormats.msoMdoc)
                            null != walletSupportedVpFormats.msoMdoc
                        }

                        else -> {
                            false
                        }
                    }
                }.foldRight(true, Boolean::and)

        ensure(walletSupportsAllRequiredVpFormats) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata(
                "Wallet does not support all required VpFormats",
            )
        }
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private fun ensureWalletSupportsVerifierClientIdPrefix(metadata: WalletMetadataTO) {
        val clientIdPrefix = verifierConfig.verifierId.clientIdPrefix
        val supportedClientPrefixes =
            metadata.clientIdPrefixesSupported
                ?: OpenId4VPSpec.DEFAULT_CLIENT_ID_PREFIXES_SUPPORTED
        ensure(clientIdPrefix in supportedClientPrefixes) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata(
                "Wallet does not support Client Id Prefix '$clientIdPrefix'",
            )
        }
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private fun ensureVerifierSupportsWalletJarSigningAlgorithms(metadata: WalletMetadataTO) {
        val jarSigningAlgorithm = verifierConfig.verifierId.accessCertificate.algorithm.name
        if (null != metadata.requestObjectSigningAlgorithmsSupported) {
            ensure(jarSigningAlgorithm in metadata.requestObjectSigningAlgorithmsSupported) {
                RetrieveRequestObjectError.UnsupportedWalletMetadata(
                    "Wallet does not support JAR Signing Algorithms '$jarSigningAlgorithm'",
                )
            }
        }
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private fun ensureWalletSupportsRequiredResponseType(metadata: WalletMetadataTO) {
        val responseType = OpenId4VPSpec.VP_TOKEN
        ensure(responseType in metadata.responseTypesSupported) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Response Type '$responseType'")
        }
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private fun ensureWalletSupportsRequiredResponseMode(
        metadata: WalletMetadataTO,
        presentation: Presentation.Requested,
    ) {
        check(presentation.channel is Channel.OverHttp)

        val responseMode =
            presentation.channel.responseMode.option
                .name()
        val supportedResponseModes = metadata.responseModesSupported ?: RFC8414.DEFAULT_RESPONSE_MODES_SUPPORTED
        ensure(responseMode in supportedResponseModes) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Response Mode '$responseMode'")
        }
    }

    context(_: Raise<RetrieveRequestObjectError>)
    private fun encryptionRequirement(metadata: WalletMetadataTO): EncryptionRequirement {
        val jwks = metadata.jwks?.toJwks()

        return if (null == jwks) {
            EncryptionRequirement.NotRequired
        } else {
            val walletSupportedEncryptionAlgorithms =
                metadata.requestObjectEncryptionAlgorithmsSupported
                    .orEmpty()
                    .map { JWEAlgorithm.parse(it) }
            val walletSupportedEncryptionMethods =
                metadata.requestObjectEncryptionMethodsSupported
                    .orEmpty()
                    .map { EncryptionMethod.parse(it) }

            EncryptionRequirement.Required
                .create(
                    jwks.keys,
                    walletSupportedEncryptionAlgorithms,
                    walletSupportedEncryptionMethods,
                )
        }
    }
}

/**
 * Transfer object for Wallet metadata.
 */
@Serializable
private data class WalletMetadataTO(
    @Required
    @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTED)
    val vpFormatsSupported: VpFormatsSupported,
    @SerialName(OpenId4VPSpec.CLIENT_ID_PREFIXES_SUPPORTED)
    val clientIdPrefixesSupported: List<String>? = OpenId4VPSpec.DEFAULT_CLIENT_ID_PREFIXES_SUPPORTED,
    @SerialName(RFC8414.JWKS)
    val jwks: JsonObject? = null,
    @SerialName(JarmSpec.AUTHORIZATION_ENCRYPTION_ALGORITHMS_SUPPORTED)
    val encryptionAlgorithmsSupported: List<String>? = null,
    @SerialName(JarmSpec.AUTHORIZATION_ENCRYPTION_METHODS_SUPPORTED)
    val encryptionMethodsSupported: List<String>? = null,
    @SerialName(RFC9101.REQUEST_OBJECT_SIGNING_ALGORITHMS_SUPPORTED)
    val requestObjectSigningAlgorithmsSupported: List<String>? = null,
    @SerialName(RFC9101.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED)
    val requestObjectEncryptionAlgorithmsSupported: List<String>? = null,
    @SerialName(RFC9101.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED)
    val requestObjectEncryptionMethodsSupported: List<String>? = null,
    @Required
    @SerialName(RFC8414.RESPONSE_TYPES_SUPPORTED)
    val responseTypesSupported: List<String>,
    @SerialName(RFC8414.RESPONSE_MODES_SUPPORTED)
    val responseModesSupported: List<String>? = RFC8414.DEFAULT_RESPONSE_MODES_SUPPORTED,
)

context(_: Raise<RetrieveRequestObjectError.UnparsableWalletMetadata>)
private fun parseWalletMetadata(serialized: String): WalletMetadataTO =
    try {
        jsonSupport.decodeFromString<WalletMetadataTO>(serialized)
    } catch (e: Exception) {
        raise(RetrieveRequestObjectError.UnparsableWalletMetadata("Wallet Metadata cannot be parsed", e))
    }

private val RetrieveRequestObjectMethod.walletMetadataOrNull: String?
    get() =
        when (this) {
            RetrieveRequestObjectMethod.Get -> null
            is RetrieveRequestObjectMethod.Post -> walletMetadata
        }

private val RetrieveRequestObjectMethod.walletNonceOrNull: String?
    get() =
        when (this) {
            RetrieveRequestObjectMethod.Get -> null
            is RetrieveRequestObjectMethod.Post -> walletNonce
        }

private val VerifierId.clientIdPrefix: String
    get() =
        when (this) {
            is VerifierId.PreRegistered -> OpenId4VPSpec.CLIENT_ID_PREFIX_PRE_REGISTERED
            is VerifierId.X509SanDns -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_SAN_DNS
            is VerifierId.X509Hash -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_HASH
        }

private fun ResponseModeOption.name(): String =
    when (this) {
        ResponseModeOption.DirectPost -> OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST
        ResponseModeOption.DirectPostJwt -> OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT
        ResponseModeOption.DcApiJwt -> error("DC API request objects are not retrieved through RetrieveRequestObject")
    }

private fun <T> commonGround(
    walletSupported: Collection<T>?,
    verifierSupported: Collection<T>?,
): Boolean =
    if (null != walletSupported && null != verifierSupported)
        walletSupported.intersect(verifierSupported.toSet()).isNotEmpty()
    else
        true

private fun commonGround(
    walletSupported: VpFormatsSupported.SdJwtVc,
    verifierSupported: VpFormatsSupported.SdJwtVc,
): Boolean {
    val sdJwtAlgorithmCommonGround =
        commonGround(
            walletSupported = walletSupported.sdJwtAlgorithms,
            verifierSupported = verifierSupported.sdJwtAlgorithms,
        )
    val kbJwtAlgorithmCommonGround =
        commonGround(
            walletSupported = walletSupported.kbJwtAlgorithms,
            verifierSupported = verifierSupported.kbJwtAlgorithms,
        )
    return sdJwtAlgorithmCommonGround && kbJwtAlgorithmCommonGround
}

context(_: Raise<RetrieveRequestObjectError.InvalidWalletMetadata>)
private fun JsonObject.toJwks(): JWKSet =
    try {
        JWKSet.parse(jsonSupport.encodeToString(this))
    } catch (e: Exception) {
        raise(RetrieveRequestObjectError.InvalidWalletMetadata("Cannot convert JsonObject to JWKS", e))
    }

context(_: Raise<RetrieveRequestObjectError>)
private fun EncryptionRequirement.Required.Companion.create(
    jwks: List<JWK>,
    algorithms: List<JWEAlgorithm>,
    methods: List<EncryptionMethod>,
): EncryptionRequirement.Required {
    ensure(jwks.isNotEmpty()) { RetrieveRequestObjectError.InvalidWalletMetadata("Missing encryption keys") }
    ensure(algorithms.isNotEmpty()) { RetrieveRequestObjectError.InvalidWalletMetadata("Missing encryption algorithms") }
    ensure(methods.isNotEmpty()) { RetrieveRequestObjectError.InvalidWalletMetadata("Missing encryption methods") }

    val encryptionRequirement =
        jwks
            .filter { it.isSupportedEncryptionJwk() }
            .firstNotNullOfOrNull { encryptionKey ->
                val encryptionKeySupportedEncryptionAlgorithms =
                    encryptionKey.supportedEncryptionAlgorithms
                        .intersect(algorithms.toSet())
                        .sortedBy { encryptionAlgorithm -> encryptionAlgorithmPreferenceMap[encryptionAlgorithm] }
                val encryptionKeySupportedEncryptionMethods =
                    encryptionKey.supportedEncryptionMethods
                        .intersect(methods.toSet())
                        .sortedBy { encryptionMethod -> encryptionMethodPreferenceMap[encryptionMethod] }
                if (encryptionKeySupportedEncryptionAlgorithms.isNotEmpty() && encryptionKeySupportedEncryptionMethods.isNotEmpty()) {
                    EncryptionRequirement.Required(
                        encryptionKey.toPublicJWK(),
                        encryptionKeySupportedEncryptionAlgorithms.first(),
                        encryptionKeySupportedEncryptionMethods.first(),
                    )
                } else {
                    null
                }
            }

    return encryptionRequirement
        ?: raise(RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet Metadata contains unsupported encryption parameters"))
}

private fun causeOf(error: RetrieveRequestObjectError): String? =
    when (error) {
        RetrieveRequestObjectError.PresentationNotFound -> {
            null
        }

        is RetrieveRequestObjectError.InvalidState -> {
            "Presentation should be in state ${error.expected.simpleName} but is in ${error.actual.simpleName}"
        }

        is RetrieveRequestObjectError.InvalidRequestUriMethod -> {
            "Invalid request_uri_method used, expected ${error.expected}"
        }

        is RetrieveRequestObjectError.UnparsableWalletMetadata -> {
            "Wallet metadata could not be parsed, reason: ${error.cause?.message ?: "n/a"}"
        }

        is RetrieveRequestObjectError.UnsupportedWalletMetadata -> {
            "Wallet metadata contains unsupported values, reason: ${error.message}, ${error.cause?.message ?: "n/a"}"
        }

        is RetrieveRequestObjectError.InvalidWalletMetadata -> {
            "Wallet metadata is not valid, reason: ${error.message}, ${error.cause?.message ?: "n/a"}"
        }
    }
