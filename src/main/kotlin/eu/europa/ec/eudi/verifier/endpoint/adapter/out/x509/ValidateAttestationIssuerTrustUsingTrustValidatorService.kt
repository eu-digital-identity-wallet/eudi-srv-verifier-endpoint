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
enum class ServiceType {
    PIDProvider,
    EAAProvider,
    QEAAProvider,
    PubEAAProvider,
    WalletProvider,
}

@Serializable
private data class TrustQuery(
    @Required @Serializable(with = NonEmptyListSerializer::class) val x5c:
        NonEmptyList<
            @Serializable(with = X509CertificateSerializer::class)
            X509Certificate,
            >,
    @Required val serviceType: ServiceType,
)

@Serializable
private data class TrustResponse(
    @Required val trusted: Boolean,
)

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
    attestations: Map<String, ServiceType>,
    defaultServiceType: ServiceType,
): ValidateAttestationIssuerTrust = ValidateAttestationIssuerTrust { issuerChain, attestationType ->
    val serviceType = attestations[attestationType] ?: defaultServiceType
    val response = httpClient.post {
        expectSuccess = true

        url(service)
        contentType(ContentType.Application.Json)
        setBody(TrustQuery(issuerChain, serviceType))

        accept(ContentType.Application.Json)
    }.body<TrustResponse>()
    if (response.trusted) AttestationIssuerTrust.Trusted else AttestationIssuerTrust.NotTrusted
}
