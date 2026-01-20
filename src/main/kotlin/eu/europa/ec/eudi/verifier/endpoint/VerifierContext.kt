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
package eu.europa.ec.eudi.verifier.endpoint

import arrow.core.*
import com.github.benmanes.caffeine.cache.Caffeine
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.util.Base64
import com.sksamuel.aedile.core.asCache
import com.sksamuel.aedile.core.expireAfterWrite
import eu.europa.ec.eudi.sdjwt.vc.*
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByReference
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByValue
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer.RefreshTrustSources
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer.ScheduleDeleteOldPresentations
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer.ScheduleTimeoutPresentations
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.TrustSources
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GenerateRequestIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GenerateTransactionIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.CreateJarNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.VerifyEncryptedResponseWithNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.keystore.loadJWK
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.keystore.loadKeyStore
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.lotl.FetchLOTLCertificatesDSS
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.IssuerSignedItemsShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.ValidityInfoShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.presentation.ValidateSdJwtVcOrMsoMdocVerifiablePresentation
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.qrcode.GenerateQrCodeFromData
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.LookupTypeMetadataFromUrl
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.ValidateJsonSchema
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist.StatusListTokenValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.ParsePemEncodedX509CertificateChainWithNimbus
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.engine.apache.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.beans.factory.BeanRegistrarDsl.SupplierContextDsl
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import java.net.URI
import java.security.KeyStore
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

private val log = LoggerFactory.getLogger(VerifierApplication::class.java)

@OptIn(ExperimentalSerializationApi::class)
internal fun beans(clock: Clock) = BeanRegistrarDsl {
    registerBean { clock }

    //
    // JOSE
    //
    registerBean { CreateJarNimbus() }
    registerBean { VerifyEncryptedResponseWithNimbus(bean<VerifierConfig>().clientMetaData.responseEncryptionOption) }

    //
    // Persistence
    //
    registerBean { GenerateTransactionIdNimbus(64) }
    registerBean { GenerateRequestIdNimbus(64) }
    with(PresentationInMemoryRepo()) {
        registerBean { loadPresentationById }
        registerBean { loadPresentationByRequestId }
        registerBean { storePresentation }
        registerBean { loadIncompletePresentationsOlderThan }
        registerBean { loadPresentationEvents }
        registerBean { publishPresentationEvent }
        registerBean { deletePresentationsInitiatedBefore }
    }

    registerBean {
        val allowedRedirectUriSchemes = env.getOptionalList(
            name = "verifier.allowedRedirectUriSchemes",
            filter = String::isNotBlank,
            transform = String::trim,
        )?.toNonEmptySet() ?: nonEmptySetOf("https")

        CreateQueryWalletResponseRedirectUri.simple(allowedRedirectUriSchemes)
    }

    //
    // Ktor
    //

    val proxy = env.getProperty("verifier.http.proxy.url")?.let {
        val url = Url(it)
        val username = env.getProperty("verifier.http.proxy.username")
        val password = env.getProperty("verifier.http.proxy.password")
        HttpProxy(url, username, password)
    }

    profile("self-signed") {
        log.warn("Using Ktor HttpClients that trust self-signed certificates and perform no hostname verification with proxy")
        registerBean<HttpClient> {
            createHttpClient(trustSelfSigned = true, httpProxy = proxy)
        }
    }
    profile("!self-signed") {
        registerBean<HttpClient> {
            createHttpClient(httpProxy = proxy)
        }
    }

    // X509
    registerBean { ParsePemEncodedX509CertificateChainWithNimbus }

    //
    // Use cases
    //
    registerBean {
        InitTransactionLive(
            bean(),
            bean(),
            bean(),
            bean(),
            bean(),
            bean(),
            bean(),
            WalletApi.requestJwtByReference(env.publicUrl()),
            bean(),
            bean(),
            bean(),
            bean(),
        )
    }

    registerBean { RetrieveRequestObjectLive(bean(), bean(), bean(), bean(), bean(), bean(), bean()) }

    registerBean {
        TimeoutPresentationsLive(
            bean(),
            bean(),
            bean<VerifierConfig>().maxAge,
            bean(),
            bean(),
        )
    }
    registerBean {
        val maxAge = Duration.parse(env.getProperty("verifier.presentations.cleanup.maxAge", "P10D"))
        require(maxAge.isPositive()) { "'verifier.presentations.cleanup.maxAge' cannot be zero or negative" }

        DeleteOldPresentationsLive(bean(), maxAge, bean())
    }

    registerBean { GenerateResponseCode.Random }
    registerBean { PostWalletResponseLive(bean(), bean(), bean(), bean(), bean(), bean(), bean(), bean(), bean()) }
    registerBean { GenerateEphemeralEncryptionKeyPairNimbus(bean<VerifierConfig>().clientMetaData.responseEncryptionOption) }
    registerBean { GetWalletResponseLive(bean(), bean(), bean()) }
    registerBean { GetPresentationEventsLive(bean(), bean()) }

    if (env.getProperty("verifier.validation.sdJwtVc.statusCheck.enabled", true)) {
        log.info("Enabling Status List Token validations")
        registerBean<StatusListTokenValidator> {
            val selfSignedProfileActive = env.activeProfiles.contains("self-signed")
            val httpClient = if (selfSignedProfileActive) {
                createHttpClient(withJsonContentNegotiation = false, trustSelfSigned = true, httpProxy = proxy)
            } else {
                createHttpClient(withJsonContentNegotiation = false, trustSelfSigned = false, httpProxy = proxy)
            }
            StatusListTokenValidator(httpClient, bean(), bean())
        }
    }

    // Default DeviceResponseValidator
    registerBean { TrustSources(revocationEnabled = false) }
    registerBean<DeviceResponseValidator> {
        val trustSources = bean<TrustSources>()
        deviceResponseValidator(trustSources::invoke)
    }

    // Default SdJwtVcValidator
    registerBean<SdJwtVcValidator> {
        val trustSources = bean<TrustSources>()
        sdJwtVcValidator(trustSources::invoke)
    }

    registerBean {
        ValidateMsoMdocDeviceResponse(
            bean(),
            bean(),
            deviceResponseValidatorFactory = { userProvided ->
                val appDefault = bean<DeviceResponseValidator>()
                userProvided?.let { deviceResponseValidator { userProvided } } ?: appDefault
            },
        )
    }
    registerBean {
        ValidateSdJwtVc(
            sdJwtVcValidatorFactory = { userProvided ->
                val appDefault = bean<SdJwtVcValidator>()
                userProvided?.let { sdJwtVcValidator { userProvided } } ?: appDefault
            },
            bean(),
        )
    }
    registerBean { ProcessSdJwtVc() }

    registerBean {
        ValidateSdJwtVcOrMsoMdocVerifiablePresentation(
            config = bean(),
            sdJwtVcValidatorFactory = { userProvided ->
                val appDefault = bean<SdJwtVcValidator>()
                userProvided?.let { sdJwtVcValidator { userProvided } } ?: appDefault
            },
            deviceResponseValidatorFactory = { userProvided ->
                val appDefault = bean<DeviceResponseValidator>()
                userProvided?.let { deviceResponseValidator { userProvided } } ?: appDefault
            },
        )
    }

    registerBean { FetchLOTLCertificatesDSS() }

    //
    // Type metadata policy
    //
    registerBean<TypeMetadataPolicy> {
        fun resolveTypeMetadata(): ResolveTypeMetadata {
            val typeMetadataResolutionProperties = bean<TypeMetadataResolutionProperties>()
            val vcts = typeMetadataResolutionProperties.vcts
                .associateBy { Vct(it.vct) }.mapValues { Url(it.value.url) }
            require(vcts.isNotEmpty()) {
                "verifier.validation.sdJwtVc.typeMetadata.resolution.vcts must be set"
            }

            val cacheTtl = Duration.parse(
                env.getProperty("verifier.validation.sdJwtVc.typeMetadata.resolution.cache.ttl", "PT1H"),
            )
            val cacheSize = env.getProperty(
                "verifier.validation.sdJwtVc.typeMetadata.resolution.cache.maxEntries",
                10,
            ).toLong()

            val cache = Caffeine.newBuilder()
                .expireAfterWrite(cacheTtl)
                .maximumSize(cacheSize)
                .asCache<Vct, ResolvedTypeMetadata>()

            val sriValidator =
                if (!typeMetadataResolutionProperties.integrity.enabled) {
                    null
                } else {
                    SRIValidator(
                        requireNotNull(typeMetadataResolutionProperties.integrity.allowedAlgorithms.toNonEmptySetOrNull()) {
                            "verifier.validation.sdJwtVc.typeMetadata.resolution.integrity.allowedAlgorithms cannot be empty"
                        },
                    )
                }
            val delegate = ResolveTypeMetadata(
                LookupTypeMetadataFromUrl(bean(), vcts, sriValidator),
                LookupJsonSchemaUsingKtor(bean(), sriValidator),
            )

            return object : ResolveTypeMetadata by delegate {
                override suspend fun invoke(
                    vct: Vct,
                    expectedIntegrity: DocumentIntegrity?,
                ): Result<ResolvedTypeMetadata> =
                    runCatching {
                        cache.get(vct) { super.invoke(vct, expectedIntegrity).getOrThrow() }
                    }
            }
        }

        val policy = env.getRequiredProperty(
            "verifier.validation.sdJwtVc.typeMetadata.policy",
            TypeMetadataPolicyEnum::class.java,
        )

        val validateJsonSchema by lazy {
            if (env.getProperty<Boolean>("verifier.validation.sdJwtVc.typeMetadata.jsonSchema.validation.enabled", true))
                ValidateJsonSchema
            else null
        }

        when (policy) {
            TypeMetadataPolicyEnum.NotUsed -> TypeMetadataPolicy.NotUsed
            TypeMetadataPolicyEnum.Optional -> TypeMetadataPolicy.Optional(resolveTypeMetadata(), validateJsonSchema)
            TypeMetadataPolicyEnum.AlwaysRequired -> TypeMetadataPolicy.AlwaysRequired(resolveTypeMetadata(), validateJsonSchema)
            TypeMetadataPolicyEnum.RequiredFor -> {
                val vcts = env.getOptionalList(
                    name = "verifier.validation.sdJwtVc.typeMetadata.policy.requiredFor",
                    filter = { it.isNotBlank() },
                )?.map { Vct(it) }?.toSet()
                requireNotNull(vcts) {
                    "verifier.validation.sdJwtVc.typeMetadata.policy.requiredFor is required when " +
                        "verifier.validation.sdJwtVc.typeMetadata.policy is 'requiredFor'"
                }

                TypeMetadataPolicy.RequiredFor(
                    vcts,
                    resolveTypeMetadata(),
                    validateJsonSchema,
                )
            }
        }
    }

    //
    // Scheduled
    //
    registerBean { ScheduleTimeoutPresentations(bean()) }
    registerBean { ScheduleDeleteOldPresentations(bean()) }
    registerBean { RefreshTrustSources(bean(), bean(), bean()) }

    //
    // Config
    //
    registerBean { verifierConfig(env) }

    //
    // End points
    //

    registerBean {
        val walletApi = WalletApi(
            bean(),
            bean(),
            bean<VerifierConfig>().verifierId.jarSigning.key,
        )
        val verifierApi = VerifierApi(
            bean(),
            bean(),
            bean(),
        )
        val staticContent = StaticContent()
        val swaggerUi = SwaggerUi(
            publicResourcesBasePath = env.getRequiredProperty("spring.webflux.static-path-pattern").removeSuffix("/**"),
            webJarResourcesBasePath = env.getRequiredProperty("spring.webflux.webjars-path-pattern")
                .removeSuffix("/**"),
        )
        val utilityApi = UtilityApi(bean(), bean(), bean())
        walletApi.route
            .and(verifierApi.route)
            .and(staticContent.route)
            .and(swaggerUi.route)
            .and(utilityApi.route)
    }

    //
    // QRCode
    //
    registerBean { GenerateQrCodeFromData }

    //
    // Other
    //
    registerBean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }

            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }
    registerBean {
        val http = bean<ServerHttpSecurity>()
        http {
            cors { // cross-origin resource sharing configuration
                configurationSource = CorsConfigurationSource {
                    CorsConfiguration().apply {
                        fun getOptionalList(name: String): NonEmptyList<String>? =
                            env.getOptionalList(name = name, filter = { it.isNotBlank() }, transform = { it.trim() })

                        allowedOrigins = getOptionalList("cors.origins")
                        allowedOriginPatterns = getOptionalList("cors.originPatterns")
                        allowedMethods = getOptionalList("cors.methods")
                        run {
                            val headers = getOptionalList("cors.headers")
                            allowedHeaders = headers
                            exposedHeaders = headers
                        }
                        allowCredentials = env.getProperty<Boolean>("cors.credentials")
                        maxAge = env.getProperty<Long>("cors.maxAge")
                    }
                }
            }
            csrf { disable() } // cross-site request forgery disabled
        }
    }
}

private fun SupplierContextDsl<*>.deviceResponseValidator(
    provideTrustSource: ProvideTrustSource,
): DeviceResponseValidator {
    val docValidator = DocumentValidator(
        clock = bean(),
        issuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
        validityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
        provideTrustSource = provideTrustSource,
        statusListTokenValidator = beanProvider<StatusListTokenValidator>().ifAvailable,
    )
    log.info(
        "Created DocumentValidator using: \n\t" +
            "IssuerSignedItemsShouldBe: '${IssuerSignedItemsShouldBe.Verified}', \n\t" +
            "ValidityInfoShouldBe: '${ValidityInfoShouldBe.NotExpired}'",
    )
    return DeviceResponseValidator(docValidator)
}

private fun SupplierContextDsl<*>.sdJwtVcValidator(
    provideTrustSource: ProvideTrustSource,
): SdJwtVcValidator = SdJwtVcValidator(
    provideTrustSource = provideTrustSource,
    audience = bean<VerifierConfig>().verifierId,
    beanProvider<StatusListTokenValidator>().ifAvailable,
    typeMetadataPolicy = bean<TypeMetadataPolicy>(),
)

private enum class EmbedOptionEnum {
    ByValue,
    ByReference,
}

private fun jarSigningConfig(environment: Environment): SigningConfig {
    val keystoreLocation = environment.getRequiredProperty("verifier.jar.signing.key.keystore")
    log.info("Will try to load Keystore from: '{}'", keystoreLocation)

    val keystoreType =
        environment.getProperty("verifier.jar.signing.key.keystore.type", KeyStore.getDefaultType())
    val keystorePassword =
        environment.getProperty("verifier.jar.signing.key.keystore.password")?.takeIf { it.isNotBlank() }
    val keyStore = loadKeyStore(keystoreLocation, keystoreType, keystorePassword)

    val keyAlias =
        environment.getRequiredProperty("verifier.jar.signing.key.alias")
    val keyPassword =
        environment.getProperty("verifier.jar.signing.key.password")?.takeIf { it.isNotBlank() }
    val key = keyStore.loadJWK(keyAlias, keyPassword)

    val algorithm = environment.getProperty("verifier.jar.signing.algorithm", "ES256").let(JWSAlgorithm::parse)
    return SigningConfig(key, algorithm)
}

private fun verifierConfig(environment: Environment): VerifierConfig {
    val verifierId = run {
        val originalClientId = environment.getProperty("verifier.originalClientId", "verifier")
        val jarSigning = jarSigningConfig(environment)

        val factory =
            when (val clientIdPrefix = environment.getProperty("verifier.clientIdPrefix", "pre-registered")) {
                "pre-registered" -> VerifierId::PreRegistered
                "x509_san_dns" -> VerifierId::X509SanDns
                "x509_hash" -> VerifierId::X509Hash
                else -> error("Unknown clientIdPrefix '$clientIdPrefix'")
            }
        factory(originalClientId, jarSigning)
    }

    val publicUrl = environment.publicUrl()
    val requestJarOption = environment.getProperty("verifier.requestJwt.embed", EmbedOptionEnum::class.java).let {
        when (it) {
            ByValue -> EmbedOption.ByValue
            ByReference, null -> WalletApi.requestJwtByReference(environment.publicUrl())
        }
    }
    val requestUriMethod = environment.getProperty<RequestUriMethod>("verifier.requestJwt.requestUriMethod") ?: RequestUriMethod.Get
    val responseModeOption =
        environment.getProperty("verifier.response.mode", ResponseModeOption::class.java)
            ?: ResponseModeOption.DirectPostJwt

    val maxAge = environment.getProperty("verifier.maxAge")?.let { Duration.parse(it) } ?: 5.minutes

    val transactionDataHashAlgorithm = environment.getProperty("verifier.transactionData.hashAlgorithm", "sha-256")
        .let { configured ->
            val hashAlgorithm = HashAlgorithm.entries.firstOrNull { supported -> supported.ianaName == configured }
            requireNotNull(hashAlgorithm) {
                "'verifier.transactionData.hashAlgorithm' must be one of '${HashAlgorithm.entries.map { it.ianaName }}'"
            }
        }

    val authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri(
        environment.getProperty("verifier.authorizationRequestUri", "haip-vp://"),
    ).getOrThrow()

    return VerifierConfig(
        verifierId = verifierId,
        requestJarOption = requestJarOption,
        requestUriMethod = requestUriMethod,
        responseUriBuilder = WalletApi.directPost(publicUrl),
        responseModeOption = responseModeOption,
        maxAge = maxAge,
        clientMetaData = environment.clientMetaData(),
        transactionDataHashAlgorithm = transactionDataHashAlgorithm,
        authorizationRequestUri = authorizationRequestUri,
        trustSourcesConfig = environment.trustSources(),
    )
}

/**
 * Parses the trust sources configuration from the environment.
 * Handles array-like property names: verifier.trustSources[0].pattern, etc.
 */
private fun Environment.trustSources(): Map<Regex, TrustSourceConfig>? {
    val trustSourcesConfigMap = mutableMapOf<Regex, TrustSourceConfig>()
    val prefix = "verifier.trustSources"

    var index = 0
    while (true) {
        val indexPrefix = "$prefix[$index]"
        val patternStr = getPropertyOrEnvVariable("$indexPrefix.pattern") ?: break
        val pattern = patternStr.toRegex()

        // Parse LOTL configuration if present
        val lotlSourceConfig = getPropertyOrEnvVariable("$indexPrefix.lotl.location")?.takeIf { it.isNotBlank() }?.let { lotlLocation ->
            val location = URI(lotlLocation).toURL()
            val serviceTypeFilter = getPropertyOrEnvVariable<ProviderKind>("$indexPrefix.lotl.serviceTypeFilter")
            val refreshInterval = getPropertyOrEnvVariable("$indexPrefix.lotl.refreshInterval", "0 0 * * * *")

            val lotlKeystoreConfig = parseKeyStoreConfig("$indexPrefix.lotl.keystore")

            TrustedListConfig(location, serviceTypeFilter, refreshInterval, lotlKeystoreConfig)
        }

        // Parse keystore configuration if present
        val keystoreConfig = parseKeyStoreConfig("$indexPrefix.keystore")

        trustSourcesConfigMap[pattern] = TrustSourcesConfig(lotlSourceConfig, keystoreConfig)

        index++
    }

    return trustSourcesConfigMap.ifEmpty {
        fallbackTrustSources()
    }
}

private fun Environment.getPropertyOrEnvVariable(property: String): String? {
    return getProperty(property) ?: getProperty(toEnvironmentVariable(property))
}

private fun Environment.getPropertyOrEnvVariable(property: String, defaultValue: String): String {
    return getProperty(property) ?: getProperty(toEnvironmentVariable(property)) ?: defaultValue
}

private inline fun <reified T> Environment.getPropertyOrEnvVariable(property: String): T? {
    return this.getProperty(key = property) ?: this.getProperty(key = toEnvironmentVariable(property))
}

private fun toEnvironmentVariable(property: String): String {
    return property.replace(".", "_")
        .replace("[", "_")
        .replace("]", "")
        .replace("-", "")
        .uppercase()
}

private fun Environment.fallbackTrustSources(): Map<Regex, TrustSourceConfig>? =
    parseKeyStoreConfig("trustedIssuers.keystore")?.let {
        mapOf(".*".toRegex() to TrustSourcesConfig(null, it))
    }

private fun Environment.parseKeyStoreConfig(propertyPrefix: String): KeyStoreConfig? = getPropertyOrEnvVariable(
    "$propertyPrefix.path",
)?.let { keystorePath ->
    val keystoreType = getPropertyOrEnvVariable("$propertyPrefix.type") ?: "JKS"
    val keystorePassword = getPropertyOrEnvVariable("$propertyPrefix.password", "")
    loadKeystore(keystorePath, keystoreType, keystorePassword)
        .onLeft { log.warn("Failed to load keystore from '$keystorePath'", it) }
        .map { KeyStoreConfig(keystorePath, keystoreType, keystorePassword, it) }
        .getOrNull()
}

private fun loadKeystore(keystorePath: String, keystoreType: String, keystorePassword: String) = Either.catch {
    DefaultResourceLoader().getResource(keystorePath)
        .inputStream
        .use {
            KeyStore.getInstance(keystoreType).apply {
                load(it, keystorePassword.toCharArray())
            }
        }
}

private fun Environment.clientMetaData(): ClientMetaData {
    val responseEncryptionOptionAlgorithm =
        getProperty("verifier.clientMetadata.responseEncryption.algorithm", JWEAlgorithm.ECDH_ES.name)

    val responseEncryptionOptionMethods =
        getOptionalList("verifier.clientMetadata.responseEncryption.methods")
            ?: nonEmptyListOf(EncryptionMethod.A128GCM.name, EncryptionMethod.A256GCM.name)

    val vpFormatsSupportedSupported = run {
        val sdJwtVc =
            if (getProperty<Boolean>("verifier.clientMetadata.vpFormats.sdJwtVc.enabled") ?: true) {
                val sdJwtAlgorithms = getOptionalList(
                    name = "verifier.clientMetadata.vpFormats.sdJwtVc.sdJwtAlgorithms",
                    filter = { it.isNotBlank() },
                )?.map(JWSAlgorithm::parse)

                val kbJwtAlgorithms = getOptionalList(
                    name = "verifier.clientMetadata.vpFormats.sdJwtVc.kbJwtAlgorithms",
                    filter = { it.isNotBlank() },
                )?.map(JWSAlgorithm::parse)

                VpFormatsSupported.SdJwtVc(sdJwtAlgorithms = sdJwtAlgorithms, kbJwtAlgorithms = kbJwtAlgorithms)
            } else null
        val msoMdoc =
            if (getProperty<Boolean>("verifier.clientMetadata.vpFormats.msoMdoc.enabled") ?: true) {
                VpFormatsSupported.MsoMdoc.Default
            } else null

        VpFormatsSupported(sdJwtVc, msoMdoc)
    }

    return ClientMetaData(
        responseEncryptionOption = ResponseEncryptionOption(
            algorithm = JWEAlgorithm.parse(responseEncryptionOptionAlgorithm),
            encryptionMethods = responseEncryptionOptionMethods.map { EncryptionMethod.parse(it) },
        ),
        vpFormatsSupported = vpFormatsSupportedSupported,
    )
}

/**
 * Gets the public URL of the Verifier endpoint. Corresponds to `verifier.publicUrl` property.
 */
private fun Environment.publicUrl(): String = getProperty("verifier.publicUrl", "http://localhost:8080")

/**
 * Gets the value of a property that contains a comma-separated list. A list is returned when it contains values.
 *
 * @receiver the configured Spring [Environment] from which to load the property
 * @param name the property to load
 * @param filter optional filter to apply to the list value
 * @param transform optional mapping to apply to the list values
 */
private fun Environment.getOptionalList(
    name: String,
    filter: (String) -> Boolean = { true },
    transform: (String) -> String = { it },
): NonEmptyList<String>? =
    this.getProperty(name)
        ?.split(",")
        ?.filter { filter(it) }
        ?.map { transform(it) }
        ?.toNonEmptyListOrNull()

/**
 * Creates an HttpClient that trusts self-signed certificates and performs no hostname verification.
 *
 * @param withJsonContentNegotiation if true, installs ContentNegotiation with JSON support
 * @param trustSelfSigned if true, configures the client to trust self-signed certificates and perform no hostname verification
 * @param httpProxy If not null, configures the client to use the provided proxy. If authentication provided, append it to the header
 */
private fun createHttpClient(
    withJsonContentNegotiation: Boolean = true,
    trustSelfSigned: Boolean = false,
    httpProxy: HttpProxy? = null,
): HttpClient =
    HttpClient(Apache) {
        if (withJsonContentNegotiation) {
            install(ContentNegotiation) {
                json(jsonSupport)
            }
        }
        expectSuccess = true
        engine {
            if (httpProxy != null) {
                proxy = ProxyBuilder.http(httpProxy.url)
            }
            followRedirects = true
            if (trustSelfSigned) {
                customizeClient {
                    setSSLContext(
                        SSLContextBuilder.create()
                            .loadTrustMaterial(TrustSelfSignedStrategy.INSTANCE)
                            .build(),
                    )
                    setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                }
            }
        }
        if (httpProxy?.username != null) {
            defaultRequest {
                val password = httpProxy.password ?: ""
                val credentials = Base64.encode("${httpProxy.username}:$password")
                header(HttpHeaders.ProxyAuthorization, "Basic $credentials")
            }
        }
    }

data class HttpProxy(
    val url: Url,
    val username: String? = null,
    val password: String? = null,
) {
    init {
        require(password == null || username != null) {
            "Password cannot be set if username is null"
        }
    }
}

private enum class TypeMetadataPolicyEnum {
    NotUsed,
    Optional,
    AlwaysRequired,
    RequiredFor,
}

@ConfigurationProperties("verifier.validation.sd-jwt-vc.type-metadata.resolution")
internal data class TypeMetadataResolutionProperties(
    val vcts: List<VctProperties> = emptyList(),
    val integrity: IntegrityProperties = IntegrityProperties(),
) {
    data class VctProperties(
        val vct: String,
        val url: String,
    )

    data class IntegrityProperties(
        val enabled: Boolean = false,
        val allowedAlgorithms: Set<IntegrityAlgorithm> = IntegrityAlgorithm.entries.toSet(),
    )
}
