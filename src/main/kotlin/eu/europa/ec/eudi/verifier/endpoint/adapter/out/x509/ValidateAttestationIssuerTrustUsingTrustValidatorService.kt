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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509

import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.serialization.NonEmptyListSerializer
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.AttestationIssuerTrust
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ValidateAttestationIssuerTrust
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64

@Serializable
enum class VerificationContext {
    PID,
    QEAA,
    PubEAA,
    EAA,
}

data class AttestationVerificationContext(
    val context: VerificationContext,
    val useCase: String? = null,
    val docTypes: NonEmptySet<String>? = null,
    val vcts: NonEmptySet<String>? = null,
) {
    init {
        if (null != useCase) {
            require(VerificationContext.EAA == context) {
                "useCase can only be provided when context is ${VerificationContext.EAA}"
            }
            require(useCase.isNotBlank()) { "useCase must not be blank" }
        }

        require(null != docTypes || null != vcts) { "either docTypes or vcts must be provided" }
    }
}

@Serializable
private data class TrustQueryTO(
    @Required @Serializable(with = NonEmptyListSerializer::class) val chain:
        NonEmptyList<
            @Serializable(with = X509CertificateSerializer::class)
            X509Certificate,
            >,
    @Required val verificationContext: VerificationContext,
    val useCase: String? = null,
)

@Serializable
private data class TrustResponseTO(
    @Required val trusted: Boolean,
    @Serializable(with = X509CertificateSerializer::class) val trustAnchor: X509Certificate? = null,
) {
    init {
        require(!trusted || null != trustAnchor) { "trustAnchor must be provided if trusted is true" }
    }
}

private object X509CertificateSerializer : KSerializer<X509Certificate> {
    private val base64 = Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        "eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.X509CertificateSerializer",
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

fun ValidateAttestationIssuerTrust.Companion.usingTrustValidatorService(
    httpClient: HttpClient,
    service: Url,
    contexts: NonEmptyList<AttestationVerificationContext>,
): ValidateAttestationIssuerTrust = ValidateAttestationIssuerTrust { issuerChain, attestationType ->
    val context = contexts.firstOrNull { attestationType in it.docTypes.orEmpty() || attestationType in it.vcts.orEmpty() }
    checkNotNull(context) { "Verification context not configured for Attestation with type $attestationType" }

    val response = httpClient.post {
        expectSuccess = true

        url(service)
        contentType(ContentType.Application.Json)
        setBody(TrustQueryTO(issuerChain, context.context, context.useCase))

        accept(ContentType.Application.Json)
    }.body<TrustResponseTO>()

    if (response.trusted) AttestationIssuerTrust.Trusted
    else AttestationIssuerTrust.NotTrusted
}
