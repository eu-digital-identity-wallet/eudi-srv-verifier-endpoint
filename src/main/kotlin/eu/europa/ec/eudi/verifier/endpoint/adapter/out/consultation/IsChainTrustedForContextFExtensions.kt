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
@file:UseSerializers(NonEmptyListSerializer::class)

package eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation

import arrow.core.NonEmptyList
import arrow.core.serialization.NonEmptyListSerializer
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainJvm
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64
import eu.europa.ec.eudi.etsi1196x2.consultation.NonEmptyList as ConsultationNonEmptyList

fun IsChainTrustedForContextF.Companion.usingTrustValidatorService(
    httpClient: HttpClient,
    service: Url,
): IsChainTrustedForContextF<NonEmptyList<X509Certificate>, VerificationContext, TrustAnchor> =
    IsChainTrustedForContextF { chain, context ->
        val response = httpClient.post {
            expectSuccess = true

            url(service)
            contentType(ContentType.Application.Json)
            setBody(TrustQueryTO(chain, VerificationContextTO.from(context), context.useCaseOrNull))

            accept(ContentType.Application.Json)
        }.body<TrustResponseTO>()

        val trustAnchor = response.trustAnchor?.let { TrustAnchor(it, null) }
        if (response.trusted) CertificationChainValidation.Trusted(
            checkNotNull(trustAnchor) { "trustAnchor cannot be null when chain is trusted" },
        )
        else CertificationChainValidation.NotTrusted(IllegalArgumentException("chain is not trusted "))
    }

@Serializable
private enum class VerificationContextTO {
    WalletInstanceAttestation,
    WalletUnitAttestation,
    WalletUnitAttestationStatus,
    PID,
    PIDStatus,
    QEAA,
    QEAAStatus,
    PubEAA,
    PubEAAStatus,
    EAA,
    EAAStatus,
    WalletRelyingPartyAccessCertificate,
    WalletRelyingPartyRegistrationCertificate,
    Custom,
    ;

    companion object {
        fun from(context: VerificationContext): VerificationContextTO =
            when (context) {
                VerificationContext.WalletInstanceAttestation -> WalletInstanceAttestation
                VerificationContext.WalletUnitAttestation -> WalletUnitAttestation
                VerificationContext.WalletUnitAttestationStatus -> WalletUnitAttestationStatus
                VerificationContext.PID -> PID
                VerificationContext.PIDStatus -> PIDStatus
                VerificationContext.QEAA -> QEAA
                VerificationContext.QEAAStatus -> QEAAStatus
                VerificationContext.PubEAA -> PubEAA
                VerificationContext.PubEAAStatus -> PubEAAStatus
                is VerificationContext.EAA -> EAA
                is VerificationContext.EAAStatus -> EAAStatus
                is VerificationContext.Custom -> Custom
                VerificationContext.WalletRelyingPartyAccessCertificate -> WalletRelyingPartyAccessCertificate
                VerificationContext.WalletRelyingPartyRegistrationCertificate -> WalletRelyingPartyRegistrationCertificate
            }
    }
}

private object X509CertificateBase64Serializer : KSerializer<X509Certificate> {
    private val base64 = Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        "eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.X509CertificateBase64Serializer",
        PrimitiveKind.STRING,
    )

    override fun serialize(encoder: Encoder, value: X509Certificate) {
        val der = value.encoded
        encoder.encodeString(base64.encode(der))
    }

    override fun deserialize(decoder: Decoder): X509Certificate {
        val der = base64.decode(decoder.decodeString())
        val factory = CertificateFactory.getInstance("X.509")
        return ByteArrayInputStream(der).use { inputStream -> factory.generateCertificate(inputStream) as X509Certificate }
    }
}

private typealias Base64X509Certificate =
    @Serializable(with = X509CertificateBase64Serializer::class)
    X509Certificate

@Serializable
private data class TrustQueryTO(
    @Required val chain: NonEmptyList<Base64X509Certificate>,
    @Required val verificationContext: VerificationContextTO,
    val useCase: String? = null,
) {
    init {
        require(
            null == useCase ||
                verificationContext in setOf(VerificationContextTO.EAA, VerificationContextTO.EAAStatus, VerificationContextTO.Custom),
        ) {
            "useCase can be used only when verificationContext is EAA, EAAStatus, or Custom"
        }
    }
}

@Serializable
private data class TrustResponseTO(
    @Required val trusted: Boolean,
    val trustAnchor: Base64X509Certificate? = null,
) {
    init {
        require(!trusted || null != trustAnchor) { "trustAnchor must be provided if trusted is true" }
    }
}

private val VerificationContext.useCaseOrNull: String?
    get() = when (this) {
        is VerificationContext.EAA -> useCase
        is VerificationContext.EAAStatus -> useCase
        is VerificationContext.Custom -> useCase
        else -> null
    }

val IsChainTrustedForContextF.Companion.Ignored: IsChainTrustedForContextF<NonEmptyList<X509Certificate>, VerificationContext, TrustAnchor>
    get() = IsChainTrustedForContextF { chain, _ ->
        CertificationChainValidation.Trusted(TrustAnchor(chain.last(), null))
    }

fun IsChainTrustedForContextF.Companion.usingTrustAnchors(
    trustAnchors: NonEmptyList<X509Certificate>,
    customization: PKIXParameters.() -> Unit = { isRevocationEnabled = false },
): IsChainTrustedForContextF<NonEmptyList<X509Certificate>, VerificationContext, TrustAnchor> =
    IsChainTrustedForContextF { chain, _ ->
        ValidateCertificateChainJvm(customization = customization)
            .invoke(
                chain = chain,
                trustAnchors = ConsultationNonEmptyList(trustAnchors.map { TrustAnchor(it, null) }),
            )
    }
