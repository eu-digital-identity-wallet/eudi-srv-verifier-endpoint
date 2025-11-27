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

import arrow.core.nonEmptyListOf
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.CreateJarNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.keystore.loadJWK
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.keystore.loadKeyStore
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.qrcode.GenerateQrCodeFromData
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.ParsePemEncodedX509CertificateChainWithNimbus
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransaction
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionLive
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateTransactionId
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.support.GenericApplicationContext
import org.springframework.core.annotation.AliasFor
import org.springframework.test.context.ContextConfiguration
import kotlin.reflect.KClass

object TestContext {
    private val testDate = LocalDateTime(1974, 11, 2, 10, 5, 33).toInstant(TimeZone.UTC)
    val testClock: Clock = Clock.fixed(testDate, TimeZone.UTC)
    val testTransactionId = TransactionId("SampleTxId")
    private val generatedTransactionId = GenerateTransactionId.fixed(testTransactionId)
    val testRequestId = RequestId("SampleRequestId")
    private val generateRequestId = GenerateRequestId.fixed(testRequestId)
    private val ecJwk: ECKey = run {
        loadKeyStore(location = "classpath:keystore.jks", type = "jks", password = "keystore")
            .loadJWK(alias = "verifier", password = "verifier")
            .toECKey()
    }
    private val responseEncryptionOption =
        ResponseEncryptionOption(JWEAlgorithm.ECDH_ES, nonEmptyListOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM))
    val clientMetaData = ClientMetaData(
        responseEncryptionOption = responseEncryptionOption,
        vpFormatsSupported = VpFormatsSupported(
            VpFormatsSupported.SdJwtVc(
                sdJwtAlgorithms = nonEmptyListOf(JWSAlgorithm.ES256),
                kbJwtAlgorithms = nonEmptyListOf(JWSAlgorithm.ES256, JWSAlgorithm.RS256),
            ),
            VpFormatsSupported.MsoMdoc(
                issuerAuthAlgorithms = null,
                deviceAuthAlgorithms = null,
            ),
        ),
    )
    private val jarSigningConfig: SigningConfig = SigningConfig(ecJwk, JWSAlgorithm.ES512)
    val verifierId = VerifierId.X509SanDns("verifier", jarSigningConfig)
    val createJar: CreateJarNimbus = CreateJarNimbus()
    val signedRequestObjectVerifier: JWSVerifier = ECDSAVerifier(ecJwk)
    private val repo = PresentationInMemoryRepo()
    val loadPresentationById = repo.loadPresentationById
    private val storePresentation = repo.storePresentation
    private val generateEphemeralKey = GenerateEphemeralEncryptionKeyPairNimbus(responseEncryptionOption)
    private val generateQrCode = GenerateQrCodeFromData

    fun initTransaction(
        verifierConfig: VerifierConfig,
        requestJarByReference: EmbedOption.ByReference<RequestId>,
    ): InitTransaction =
        InitTransactionLive(
            generatedTransactionId,
            generateRequestId,
            storePresentation,
            createJar,
            verifierConfig,
            testClock,
            generateEphemeralKey,
            requestJarByReference,
            CreateQueryWalletResponseRedirectUri.simple("https"),
            repo.publishPresentationEvent,
            ParsePemEncodedX509CertificateChainWithNimbus,
            generateQrCode,
        )
}

/**
 * Meta annotation to be used with integration tests of the application
 */
@Target(AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@SpringBootTest(
    classes = [VerifierApplication::class],
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
)
@ContextConfiguration(initializers = [BeansDslApplicationContextInitializer::class])
internal annotation class VerifierApplicationTest(

    /**
     * [Configuration] classes that contain extra bean definitions.
     * Useful for bean overriding using [Primary] annotation.
     */
    @get:AliasFor(annotation = ContextConfiguration::class)
    val classes: Array<KClass<*>> = [],

)

/**
 * [ApplicationContextInitializer] for use with [SpringBootTest]/[ContextConfiguration]
 */
internal class BeansDslApplicationContextInitializer : ApplicationContextInitializer<GenericApplicationContext> {
    override fun initialize(applicationContext: GenericApplicationContext) {
        applicationContext.register(beans(Clock.System))
    }
}
