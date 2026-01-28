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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert

import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.toJavaDate
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import kotlin.time.Duration
import kotlin.time.Instant

internal object CertOps {
    private val Ctx = SecCtx(null)

    private val clock = Clock.System

    private var serialNumberBase: Long = System.currentTimeMillis()

    @Synchronized
    private fun calculateSerialNumber(): BigInteger = BigInteger.valueOf(serialNumberBase++)

    private fun calculateDate(hoursInFuture: Int): Date {
        val secs = System.currentTimeMillis() / 1000
        return Date((secs + (hoursInFuture * 60 * 60)) * 1000)
    }

    private fun notBefore(d: Duration = Duration.ZERO): Instant =
        (clock.now() + d)

    fun genTrustAnchor(
        sigAlg: String,
        name: X500Name,
    ): Pair<KeyPair, X509CertificateHolder> {
        val kp = Ctx.generateECPair()
        val certHolder = createTrustAnchor(kp, sigAlg, name)
        return kp to certHolder
    }

    fun genIntermediateCertificate(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        followingCACerts: Int = 0,
        subject: X500Name,
    ): Pair<KeyPair, X509CertificateHolder> {
        val caKp = Ctx.generateECPair()
        val caCertHolder =
            createIntermediateCertificate(signerCert, signerKey, sigAlg, caKp.public, followingCACerts, subject)
        return caKp to caCertHolder
    }

    fun genEndEntity(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        subject: X500Name,
    ): Pair<KeyPair, X509CertificateHolder> {
        val eeKp = Ctx.generateECPair()
        val eeCertHolder = createEndEntity(signerCert, signerKey, sigAlg, eeKp.public, subject)
        return eeKp to eeCertHolder
    }

    /**
     * Build a sample self-signed V1 certificate to use as a trust anchor, or
     *  root certificate.
     */
    fun createTrustAnchor(
        keyPair: KeyPair,
        sigAlg: String,
        name: X500Name,
    ): X509CertificateHolder {
        return JcaX509v1CertificateBuilder(
            name,
            calculateSerialNumber(),
            notBefore().toJavaDate(),
            calculateDate(24 * 31),
            name,
            keyPair.public,
        ).build(sigAlg, keyPair.private)
    }

    /**
     * Build a sample V3 intermediate certificate that can be used as a CA
     *  certificate.
     *  @param signerCert certificate carrying the public key that will late
     *  be used to verify this certificate's signature
     *  @param signerKey private key used to generate the signature in the certificate
     *  @param certKey public key to be installed in the certificate.
     */
    fun createIntermediateCertificate(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        certKey: PublicKey,
        followingCACerts: Int = 0,
        subject: X500Name,
    ): X509CertificateHolder =
        JcaX509v3CertificateBuilder(
            signerCert.subject,
            calculateSerialNumber(),
            notBefore().toJavaDate(),
            calculateDate(24 * 31),
            subject,
            certKey,
        ).apply {
            authorityKeyIdentifier(signerCert)
            subjectKeyIdentifier(certKey)
            basicConstraints(BasicConstraints(followingCACerts)) // allow this cert to sign other certs
            keyUsage(KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign))
        }.build(sigAlg, signerKey)

    fun createEndEntity(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        certKey: PublicKey,
        subject: X500Name,
    ): X509CertificateHolder =
        JcaX509v3CertificateBuilder(
            signerCert.subject,
            calculateSerialNumber(),
            notBefore().toJavaDate(),
            calculateDate(24 * 31),
            subject,
            certKey,
        ).apply {
            authorityKeyIdentifier(signerCert)
            subjectKeyIdentifier(certKey)
            basicConstraints(BasicConstraints(false)) // do not allow this cert to sign other certs
            keyUsage(KeyUsage(KeyUsage.digitalSignature))
        }.build(sigAlg, signerKey)

    private fun signer(sigAlg: String, privateKey: PrivateKey): ContentSigner =
        Ctx.jcaContentSignerBuilder(sigAlg).build(privateKey)

    fun X509CertificateHolder.toCertificate(): X509Certificate {
        val cFact = Ctx.certFactory()
        return cFact.generateCertificate(encoded.inputStream()) as X509Certificate
    }

    private fun JcaX509v1CertificateBuilder.build(sigAlg: String, privateKey: PrivateKey): X509CertificateHolder {
        val signer = signer(sigAlg, privateKey)
        return build(signer)
    }
    private fun JcaX509v3CertificateBuilder.build(sigAlg: String, privateKey: PrivateKey): X509CertificateHolder {
        val signer = signer(sigAlg, privateKey)
        return build(signer)
    }
}

//
// Kotlin extensions
//

private fun JcaX509v3CertificateBuilder.authorityKeyIdentifier(signerCert: X509CertificateHolder) {
    addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(signerCert))
}

private fun JcaX509v3CertificateBuilder.subjectKeyIdentifier(certKey: PublicKey) {
    addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certKey))
}

private fun JcaX509v3CertificateBuilder.keyUsage(keyUsage: KeyUsage) {
    addExtension(Extension.keyUsage, true, keyUsage)
}

/**
 * The BasicConstraints extension helps you to determine if the certificate containing it is allowed to
 * sign other certificates, and if so, what depth this can go to.
 *
 * So, for example, if cA is TRUE and the pathLenConstraint is 0, then the certificate, as far as this extension
 * is concerned, is allowed to sign other certificates, but none of the certificates so signed can be used to sign other certificates and lengthen
 * the chain.
 *
 */
private fun JcaX509v3CertificateBuilder.basicConstraints(c: BasicConstraints) {
    addExtension(Extension.basicConstraints, true, c)
}

private val extUtils = JcaX509ExtensionUtils()

private class SecCtx(private val provider: Provider? = null) {

    fun certFactory(): CertificateFactory =
        provider
            ?.let { CertificateFactory.getInstance("X.509", it) }
            ?: CertificateFactory.getInstance("X.509")

    fun kpGenerator(): KeyPairGenerator =
        provider
            ?.let { KeyPairGenerator.getInstance("EC", provider) }
            ?: KeyPairGenerator.getInstance("EC")

    fun generateECPair(): KeyPair = kpGenerator().genKeyPair()

    fun jcaContentSignerBuilder(sigAlg: String) =
        JcaContentSignerBuilder(sigAlg).apply {
            if (provider != null) {
                setProvider(provider)
            }
        }
}
