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
@file:OptIn(ExperimentalSerializationApi::class)

package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.*
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import com.eygraber.uri.Uri
import com.eygraber.uri.Url
import com.eygraber.uri.toURI
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.isSelfSigned
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption
import eu.europa.ec.eudi.verifier.endpoint.domain.EncryptionRequirement
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseMode.OverDcApi.*
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseMode.OverHttp.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateTransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.CreateJar
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.GenerateQrCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.Pixels.Companion.pixels
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.by
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509Certificates
import kotlinx.serialization.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate

/**
 * Specifies request_uri_method for a request
 */
@Serializable
enum class RequestUriMethodTO {
    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD_GET)
    Get,

    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD_POST)
    Post,

    @SerialName("post_get")
    PostOrGet,
}

/**
 * Specifies the response_mode for a request
 */
@Serializable
enum class ResponseModeTO {
    @SerialName(OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST)
    DirectPost,

    @SerialName(OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT)
    DirectPostJwt,

    @SerialName(OpenId4VPSpec.RESPONSE_MODE_DCAPI_JWT)
    DcApiJwt,
}

/**
 * Specifies whether a property of a request will be provided by value or by reference.
 */
@Serializable
enum class EmbedModeTO {
    @SerialName("by_value")
    ByValue,

    @SerialName("by_reference")
    ByReference,
}

/**
 * The Profile to active for a Transaction.
 */
@Serializable
enum class ProfileTO {
    /**
     * Initialize a Transaction per OpenId4VP. No constraints are enforced.
     */
    @SerialName("openid4vp")
    OpenId4VP,

    /**
     * Initialize a Transaction per HAIP. Extra constraints are enforced.
     */
    @SerialName("haip")
    HAIP,
}

@Serializable
data class InitTransactionTO(
    @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: DCQL? = null,
    @SerialName(OpenId4VPSpec.NONCE) val nonce: String? = null,
    @SerialName(RFC6749.RESPONSE_MODE) val responseMode: ResponseModeTO? = null,
    @SerialName("jar_mode") val jarMode: EmbedModeTO? = null,
    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD) val requestUriMethod: RequestUriMethodTO? = null,
    @SerialName("wallet_response_redirect_uri_template") val redirectUriTemplate: String? = null,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: List<JsonObject>? = null,
    @SerialName("issuer_chain") val issuerChain: String? = null,
    @SerialName("authorization_request_scheme") val authorizationRequestScheme: String? = null,
    @SerialName("authorization_request_uri") val authorizationRequestUri: String? = null,
    @SerialName("profile") val profile: ProfileTO? = ProfileTO.OpenId4VP,
    @Transient val output: Output = Output.Json,
)

private val InitTransactionTO.profileOrDefault: ProfileTO
    get() = profile ?: ProfileTO.OpenId4VP

/**
 * Possible validation errors of caller's input
 */
sealed interface ValidationError {
    data object MissingPresentationQuery : ValidationError

    data object MissingNonce : ValidationError

    data object InvalidWalletResponseTemplate : ValidationError

    data object InvalidTransactionData : ValidationError

    data object UnsupportedFormat : ValidationError

    data object InvalidIssuerChain : ValidationError

    data object ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme : ValidationError

    data object InvalidAuthorizationRequestUri : ValidationError

    data object InvalidAuthorizationRequestScheme : ValidationError

    sealed interface HaipNotSupported : ValidationError {
        data object SdJwtVcOrMsoMdocMustBeSupported : HaipNotSupported

        data object JwsAlgorithmES256MustBeSupported : HaipNotSupported

        data object ClientIdPrefixX509HashMustBeUsed : HaipNotSupported

        data object SelfSignedCertificateMustNotBeUsed : HaipNotSupported

        data object EncryptionAlgorithmECDHESMustBeSupported : HaipNotSupported

        data object EncryptionMethodsA128GCMAndA256GCMMustBeSupported : HaipNotSupported

        data object ResponseModeDirectPostJwtMustBeUsed : HaipNotSupported

        data object AuthorizationRequestMustBeProvidedByReference : HaipNotSupported
    }
}

enum class Output {
    Json,
    QrCode,
}

sealed interface InitTransactionResponse {
    /**
     * The return value of successfully [initializing][InitTransaction] a [Presentation] as a QR Code
     *
     */
    data class QrCode(
        val qrCode: ByteArray,
        val transactionId: String,
        val authorizationRequestUri: String,
    ) : InitTransactionResponse {
        override fun equals(other: Any?): Boolean =
            other is QrCode &&
                qrCode.contentEquals(other.qrCode) &&
                transactionId == other.transactionId &&
                authorizationRequestUri == other.authorizationRequestUri

        override fun hashCode(): Int {
            var result = qrCode.contentHashCode()
            result = 31 * result + transactionId.hashCode()
            result = 31 * result + authorizationRequestUri.hashCode()
            return result
        }
    }

    /**
     * The return value of successfully [initializing][InitTransaction] a [Presentation] as a JSON
     *
     */
    @Serializable
    data class JwtSecuredAuthorizationRequestTO(
        @Required @SerialName("transaction_id") val transactionId: String,
        @Required @SerialName(RFC6749.CLIENT_ID) val clientId: ClientId,
        @SerialName(RFC9101.REQUEST) val request: String?,
        @SerialName(RFC9101.REQUEST_URI) val requestUri: String?,
        @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD) val requestUriMethod: RequestUriMethodTO?,
        @SerialName("authorization_request_uri") val authorizationRequestUri: String,
    ) : InitTransactionResponse {
        companion object {
            fun byValue(
                transactionId: String,
                clientId: ClientId,
                request: String,
                authorizationRequestUri: URI,
            ): JwtSecuredAuthorizationRequestTO =
                JwtSecuredAuthorizationRequestTO(
                    transactionId,
                    clientId,
                    request,
                    null,
                    null,
                    authorizationRequestUri.toString(),
                )

            fun byReference(
                transactionId: String,
                clientId: ClientId,
                requestUri: URL,
                requestUriMethod: RequestUriMethodTO,
                authorizationRequestUri: URI,
            ): JwtSecuredAuthorizationRequestTO =
                JwtSecuredAuthorizationRequestTO(
                    transactionId,
                    clientId,
                    null,
                    requestUri.toExternalForm(),
                    requestUriMethod,
                    authorizationRequestUri.toString(),
                )
        }
    }
}

/**
 * This is a use case that initializes the [Presentation] process.
 *
 * Use case will initialize a [Presentation] process
 */
interface InitTransaction {
    context(_: Raise<ValidationError>)
    suspend operator fun invoke(initTransactionTO: InitTransactionTO): InitTransactionResponse

    context(_: Raise<ValidationError>)
    suspend operator fun invoke(initDcApiTransactionTO: InitDcApiTransactionTO): InitDcApiTransactionResponseTO
}

/**
 * The default implementation of the use case
 */
class InitTransactionLive(
    private val generateTransactionId: GenerateTransactionId,
    private val generateRequestId: GenerateRequestId,
    private val storePresentation: StorePresentation,
    private val createJar: CreateJar,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val generateEphemeralEncryptionKeyPair: GenerateEphemeralEncryptionKeyPair,
    private val requestJarByReference: EmbedOption.ByReference<RequestId>,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val parsePemEncodedX509CertificateChain: ParsePemEncodedX509Certificates,
    private val generateQrCode: GenerateQrCode,
) : InitTransaction {
    context(_: Raise<ValidationError>)
    override suspend fun invoke(initTransactionTO: InitTransactionTO): InitTransactionResponse {
        // validate input
        val (nonce, type) =
            context(verifierConfig.transactionDataHashAlgorithm, verifierConfig.clientMetaData.vpFormatsSupported) {
                validate(
                    initTransactionTO.dcqlQuery,
                    initTransactionTO.nonce,
                    initTransactionTO.transactionData,
                )
            }

        // if response mode is direct post jwt then generate ephemeral key
        val responseMode = responseMode(initTransactionTO.responseMode)
        check(responseMode is ResponseMode.OverHttp)

        val channel =
            Channel.OverHttp(
                responseMode = responseMode,
                requestUriMethod = requestUriMethod(initTransactionTO.requestUriMethod),
                getWalletResponseMethod = getWalletResponseMethod(initTransactionTO.redirectUriTemplate),
                requestId = generateRequestId(),
            )

        val issuerChain = issuerChain(initTransactionTO.issuerChain)
        val profile = initTransactionTO.profileOrDefault.toProfile()
        val jarMode = jarMode(initTransactionTO)

        // validate according to the selected profile
        with(profile.validator) {
            context(verifierConfig) {
                validate(channel, jarMode)
            }
        }

        // create the request, which may update the presentation
        val unresolvedAuthorizationRequestUri =
            with(verifierConfig) {
                authorizationRequestUri(
                    initTransactionTO.authorizationRequestUri,
                    initTransactionTO.authorizationRequestScheme,
                )
            }

        // Initialize presentation
        val (presentation, authorizationRequest) =
            when (jarMode) {
                is EmbedOption.ByReference -> {
                    val presentation =
                        Presentation.Requested(
                            id = generateTransactionId(),
                            initiatedAt = clock.now(),
                            query = type.query,
                            transactionData = type.transactionData,
                            nonce = nonce,
                            issuerChain = issuerChain,
                            profile = profile,
                            channel = channel,
                        )

                    val requestUri = jarMode.buildUrl(presentation.channel.requestId)
                    val authorizationRequest =
                        InitTransactionResponse.JwtSecuredAuthorizationRequestTO.byReference(
                            presentation.id.value,
                            verifierConfig.verifierId.clientId,
                            requestUri,
                            presentation.channel.requestUriMethod.toTO(),
                            unresolvedAuthorizationRequestUri
                                .resolve(
                                    verifierConfig.verifierId,
                                    Uri.parse(requestUri.toString()),
                                    presentation.channel.requestUriMethod,
                                ).toURI(),
                        )
                    presentation to authorizationRequest
                }

                EmbedOption.ByValue -> {
                    val presentation =
                        Presentation.RequestObjectRetrieved(
                            id = generateTransactionId(),
                            initiatedAt = clock.now(),
                            channel = channel,
                            query = type.query,
                            transactionData = type.transactionData,
                            requestObjectRetrievedAt = clock.now(),
                            nonce = nonce,
                            issuerChain = issuerChain,
                            profile = profile,
                        )

                    val jar =
                        createJar(
                            clock.now(),
                            presentation.transactionData,
                            presentation.channel,
                            presentation.query,
                            presentation.nonce,
                            null,
                            EncryptionRequirement.NotRequired,
                        )
                    val authorizationRequest =
                        InitTransactionResponse.JwtSecuredAuthorizationRequestTO.byValue(
                            presentation.id.value,
                            verifierConfig.verifierId.clientId,
                            jar,
                            unresolvedAuthorizationRequestUri.resolve(verifierConfig.verifierId, jar).toURI(),
                        )
                    presentation to authorizationRequest
                }
            }

        val response =
            when (initTransactionTO.output) {
                Output.Json -> {
                    authorizationRequest
                }

                Output.QrCode -> {
                    InitTransactionResponse.QrCode(
                        generateQrCode(authorizationRequest.authorizationRequestUri, size = (250.pixels by 250.pixels)),
                        authorizationRequest.transactionId,
                        authorizationRequest.authorizationRequestUri,
                    )
                }
            }

        storePresentation(presentation)
        logTransactionInitialized(presentation, authorizationRequest, profile)

        return response
    }

    context(_: Raise<ValidationError>)
    override suspend fun invoke(initDcApiTransactionTO: InitDcApiTransactionTO): InitDcApiTransactionResponseTO {
        val jarMode = EmbedOption.ByValue
        val profile = Profile.ETSI119472Part2

        // validate input
        val (nonce, type) =
            context(verifierConfig.transactionDataHashAlgorithm, verifierConfig.clientMetaData.vpFormatsSupported) {
                validate(
                    initDcApiTransactionTO.dcqlQuery,
                    initDcApiTransactionTO.nonce,
                    initDcApiTransactionTO.transactionData,
                )
            }
        // if response mode is direct post jwt then generate ephemeral key
        val responseMode = responseMode(ResponseModeTO.DcApiJwt)
        check(responseMode is ResponseMode.OverDcApi)

        val issuerChain = issuerChain(initDcApiTransactionTO.issuerChain)
        val origin = initDcApiTransactionTO.origin

        val channel =
            Channel.OverDcApi(
                responseMode = responseMode,
                origin = origin,
            )

        // validate according to the selected profile
        with(profile.validator) {
            context(verifierConfig) {
                validate(channel, jarMode)
            }
        }

        // Initialize presentation
        val requestedPresentation =
            Presentation.RequestObjectRetrieved(
                id = generateTransactionId(),
                initiatedAt = clock.now(),
                channel = channel,
                query = type.query,
                requestObjectRetrievedAt = clock.now(),
                nonce = nonce,
                transactionData = type.transactionData,
                issuerChain = issuerChain,
                profile = profile,
            )

        val jwt =
            createJar(
                clock.now(),
                requestedPresentation.transactionData,
                requestedPresentation.channel,
                requestedPresentation.query,
                requestedPresentation.nonce,
                null,
                EncryptionRequirement.NotRequired,
            )

        storePresentation(requestedPresentation)
        logTransactionInitialized(requestedPresentation, jwt)

        return InitDcApiTransactionResponseTO(
            jwt,
            requestedPresentation.id.value,
        )
    }

    /**
     * Gets the JAR [RequestUriMethod] for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.requestUriMethod].
     */
    private fun requestUriMethod(requestUriMethod: RequestUriMethodTO?): RequestUriMethod =
        when (requestUriMethod) {
            RequestUriMethodTO.Get -> RequestUriMethod.Get
            RequestUriMethodTO.Post -> RequestUriMethod.Post
            RequestUriMethodTO.PostOrGet -> RequestUriMethod.PostOrGet
            null -> verifierConfig.requestUriMethod
        }

    context(_: Raise<ValidationError>)
    private fun getWalletResponseMethod(redirectUriTemplate: String?): GetWalletResponseMethod =
        redirectUriTemplate
            ?.let { template ->
                with(createQueryWalletResponseRedirectUri) {
                    ensure(template.validTemplate()) { ValidationError.InvalidWalletResponseTemplate }
                }
                GetWalletResponseMethod.Redirect(template)
            } ?: GetWalletResponseMethod.Poll

    /**
     * Gets the [ResponseMode] for the provided [InitTransactionTO].
     */
    private suspend fun responseMode(responseMode: ResponseModeTO?): ResponseMode {
        val responseModeOption =
            when (responseMode) {
                ResponseModeTO.DirectPost -> ResponseModeOption.DirectPost
                ResponseModeTO.DirectPostJwt -> ResponseModeOption.DirectPostJwt
                ResponseModeTO.DcApiJwt -> ResponseModeOption.DcApiJwt
                null -> verifierConfig.responseModeOption
            }

        return when (responseModeOption) {
            ResponseModeOption.DirectPost -> {
                DirectPost
            }

            ResponseModeOption.DirectPostJwt -> {
                val responseEncryptionKey = generateEphemeralEncryptionKeyPair()
                DirectPostJwt(responseEncryptionKey)
            }

            ResponseModeOption.DcApiJwt -> {
                val responseEncryptionKey = generateEphemeralEncryptionKeyPair()
                DcApiJwt(responseEncryptionKey)
            }
        }
    }

    /**
     * Gets the JAR [EmbedOption] for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.requestJarOption].
     */
    private fun jarMode(initTransaction: InitTransactionTO): EmbedOption<RequestId> =
        when (initTransaction.jarMode) {
            EmbedModeTO.ByValue -> EmbedOption.ByValue
            EmbedModeTO.ByReference -> requestJarByReference
            null -> verifierConfig.requestJarOption
        }

    private suspend fun logTransactionInitialized(
        presentation: Presentation,
        request: InitTransactionResponse.JwtSecuredAuthorizationRequestTO,
        profile: Profile,
    ) {
        val event =
            PresentationEvent.TransactionInitialized(
                presentation.id,
                presentation.initiatedAt,
                request,
                profile,
            )
        publishPresentationEvent(event)
    }

    private suspend fun logTransactionInitialized(
        presentation: Presentation.RequestObjectRetrieved,
        request: Jwt,
    ) {
        val event =
            PresentationEvent.DcApiTransactionInitialized(
                presentation.id,
                presentation.initiatedAt,
                request,
                Profile.ETSI119472Part2,
            )
        publishPresentationEvent(event)
    }

    context(_: Raise<ValidationError.InvalidIssuerChain>)
    private fun issuerChain(issuerChain: String?): NonEmptyList<X509Certificate>? =
        catch(
            block = { issuerChain?.let { parsePemEncodedX509CertificateChain(it) } },
            catch = { raise(ValidationError.InvalidIssuerChain) },
        )
}

/**
 * Gets the [UnresolvedAuthorizationRequestUri] for the provided [authorizationRequestUri] and [authorizationRequestScheme].
 * If none has been provided, falls back to [VerifierConfig.authorizationRequestUri].
 *
 * This method considers both [authorizationRequestUri] and [authorizationRequestScheme].
 */
context(_: Raise<ValidationError>, verifierConfig: VerifierConfig)
private fun authorizationRequestUri(
    authorizationRequestUri: String?,
    authorizationRequestScheme: String?,
): UnresolvedAuthorizationRequestUri =
    when {
        null != authorizationRequestUri && null != authorizationRequestScheme -> {
            raise(ValidationError.ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme)
        }

        null != authorizationRequestUri -> {
            UnresolvedAuthorizationRequestUri.fromUri(authorizationRequestUri).getOrElse {
                raise(ValidationError.InvalidAuthorizationRequestUri)
            }
        }

        null != authorizationRequestScheme -> {
            UnresolvedAuthorizationRequestUri.fromScheme(authorizationRequestScheme).getOrElse {
                raise(ValidationError.InvalidAuthorizationRequestScheme)
            }
        }

        else -> {
            verifierConfig.authorizationRequestUri
        }
    }

context(_: Raise<ValidationError>, transactionDataHashAlgorithm: HashAlgorithm, vpFormatsSupported: VpFormatsSupported)
internal fun validate(
    dcqlQuery: DCQL?,
    nonce: String?,
    transactionData: List<JsonObject>?,
): Pair<Nonce, VpTokenRequest> {
    fun requiredQuery(): DCQL {
        ensureNotNull(dcqlQuery) { ValidationError.MissingPresentationQuery }
        ensure(
            dcqlQuery.credentials.value.all {
                val format = it.format
                vpFormatsSupported.supports(format)
            },
        ) { ValidationError.UnsupportedFormat }

        return dcqlQuery
    }

    fun requiredNonce(): Nonce {
        ensure(!nonce.isNullOrBlank()) { ValidationError.MissingNonce }
        return Nonce(nonce)
    }

    fun optionalTransactionData(query: DCQL): NonEmptyList<TransactionData>? {
        val credentialIds: List<String> by lazy {
            query.credentials.ids.map { it.value }
        }

        val hashAlgorithms: JsonArray by lazy {
            buildJsonArray {
                add(transactionDataHashAlgorithm.ianaName)
            }
        }

        return transactionData
            ?.map {
                TransactionData
                    .validate(
                        JsonObject(it + (OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS to hashAlgorithms)),
                        credentialIds,
                    ).flatMap { transactionData ->
                        Either.catch {
                            when (transactionData.type) {
                                QesApproval.TYPE -> QesApproval.serializer()
                                QesRequest.TYPE -> QesRequest.serializer()
                                else -> null
                            }?.let { deserializer -> it.decodeAs(deserializer) }
                            transactionData
                        }
                    }.getOrElse { raise(ValidationError.InvalidTransactionData) }
            }?.toNonEmptyListOrNull()
    }

    val query = requiredQuery()
    val presentationType = VpTokenRequest(query, optionalTransactionData(query))
    val nonce = requiredNonce()

    return nonce to presentationType
}

private fun RequestUriMethod.toTO(): RequestUriMethodTO =
    when (this) {
        RequestUriMethod.Get -> RequestUriMethodTO.Get
        RequestUriMethod.Post -> RequestUriMethodTO.Post
        RequestUriMethod.PostOrGet -> RequestUriMethodTO.PostOrGet
    }

private fun <T : Any, U : T> Collection<T>.containsAny(
    first: U,
    vararg rest: U,
): Boolean = first in this || rest.any { it in this }

private fun interface ProfileValidator {
    context(_: Raise<ValidationError>, config: VerifierConfig)
    suspend fun validate(
        channel: Channel,
        jarMode: EmbedOption<RequestId>,
    )

    companion object {
        val OpenId4VP = ProfileValidator { _, _ -> }
        val HAIP =
            ProfileValidator { channel, jarMode ->
                val config = contextOf<VerifierConfig>()
                with(config.clientMetaData.vpFormatsSupported) {
                    ensure(null != sdJwtVc || null != msoMdoc) {
                        ValidationError.HaipNotSupported.SdJwtVcOrMsoMdocMustBeSupported
                    }

                    if (null != sdJwtVc) {
                        ensure(null == sdJwtVc.sdJwtAlgorithms || JWSAlgorithm.ES256 in sdJwtVc.sdJwtAlgorithms) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }
                        ensure(null == sdJwtVc.kbJwtAlgorithms || JWSAlgorithm.ES256 in sdJwtVc.kbJwtAlgorithms) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }
                    }

                    if (null != msoMdoc) {
                        ensure(
                            null == msoMdoc.issuerAuthAlgorithms ||
                                msoMdoc.issuerAuthAlgorithms.containsAny(CoseAlgorithm(-7), CoseAlgorithm(-9)),
                        ) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }

                        ensure(
                            null == msoMdoc.deviceAuthAlgorithms ||
                                msoMdoc.deviceAuthAlgorithms.containsAny(CoseAlgorithm(-7), CoseAlgorithm(-9)),
                        ) {
                            ValidationError.HaipNotSupported.JwsAlgorithmES256MustBeSupported
                        }
                    }
                }

                with(config.clientMetaData.responseEncryptionOption) {
                    ensure(JWEAlgorithm.ECDH_ES == algorithm) {
                        ValidationError.HaipNotSupported.EncryptionAlgorithmECDHESMustBeSupported
                    }

                    ensure(encryptionMethods.containsAll(listOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM))) {
                        ValidationError.HaipNotSupported.EncryptionMethodsA128GCMAndA256GCMMustBeSupported
                    }
                }

                ensure(config.verifierId is VerifierId.X509Hash) {
                    ValidationError.HaipNotSupported.ClientIdPrefixX509HashMustBeUsed
                }
                ensure(
                    !config.verifierId.accessCertificate.certificate
                        .isSelfSigned(),
                ) {
                    ValidationError.HaipNotSupported.SelfSignedCertificateMustNotBeUsed
                }
                when (channel) {
                    is Channel.OverDcApi -> {
                        ensure(jarMode is EmbedOption.ByValue) {
                            ValidationError.HaipNotSupported.AuthorizationRequestMustBeProvidedByReference
                        }
                    }

                    is Channel.OverHttp -> {
                        ensure(channel.responseMode is DirectPostJwt) {
                            ValidationError.HaipNotSupported.ResponseModeDirectPostJwtMustBeUsed
                        }
                        ensure(jarMode is EmbedOption.ByReference) {
                            ValidationError.HaipNotSupported.AuthorizationRequestMustBeProvidedByReference
                        }
                    }
                }
            }

        val ETSI119472Part2 =
            ProfileValidator { channel, jarMode ->
                HAIP.validate(channel, jarMode)
            }
    }
}

private fun ProfileTO.toProfile(): Profile =
    when (this) {
        ProfileTO.OpenId4VP -> Profile.OpenId4VP
        ProfileTO.HAIP -> Profile.HAIP
    }

private val Profile.validator: ProfileValidator
    get() =
        when (this) {
            Profile.OpenId4VP -> ProfileValidator.OpenId4VP
            Profile.HAIP -> ProfileValidator.HAIP
            Profile.ETSI119472Part2 -> ProfileValidator.ETSI119472Part2
        }

@Serializable
data class InitDcApiTransactionTO(
    @Required @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: DCQL,
    @Required @SerialName(OpenId4VPSpec.NONCE) val nonce: String,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: List<JsonObject>? = null,
    @SerialName("issuer_chain") val issuerChain: String? = null,
    @Required @SerialName("origin") val origin: Url,
)

@Serializable
data class InitDcApiTransactionResponseTO(
    @Required
    @SerialName("request")
    val request: String,
    @Required
    @SerialName("transaction_id")
    val transactionId: String,
)
