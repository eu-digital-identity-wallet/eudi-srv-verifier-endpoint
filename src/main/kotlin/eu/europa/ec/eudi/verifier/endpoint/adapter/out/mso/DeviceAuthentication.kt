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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mdocauth.DeviceAuthentication
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import java.net.URL
import java.security.MessageDigest

operator fun DeviceAuthentication.Companion.invoke(
    sessionTranscript: SessionTranscript,
    docType: String,
    deviceNameSpaces: DeviceNameSpaces,
): DeviceAuthentication = DeviceAuthentication(
    sessionTranscript = sessionTranscript.toListElement(),
    docType = docType,
    deviceNameSpaces = deviceNameSpaces.toEncodedCborElement(),
)

@JvmInline
value class DeviceNameSpaces(val nameSpaces: Map<String, DeviceSignedItems>) {
    fun toMapElement(): MapElement =
        buildMap {
            nameSpaces.forEach { (nameSpace, deviceSignedItems) -> put(MapKey(nameSpace), deviceSignedItems.toMapElement()) }
        }.toDataElement()

    fun toCbor(): ByteArray = waltIdCbor.encodeToByteArray(toMapElement())
    fun toCborHex(): String = waltIdCbor.encodeToHexString(toMapElement())
    fun toEncodedCborElement(): EncodedCBORElement = EncodedCBORElement(toCbor())

    companion object {
        fun empty(): DeviceNameSpaces = DeviceNameSpaces(emptyMap())

        fun fromDocument(document: MDoc): DeviceNameSpaces =
            buildMap {
                document.nameSpaces.forEach { nameSpace ->
                    document.getIssuerSignedItems(nameSpace).map { issuerSignedItem ->
                        DeviceSignedItem(issuerSignedItem.elementIdentifier.value, issuerSignedItem.elementValue)
                    }.toNonEmptyListOrNull()
                        ?.let { put(nameSpace, DeviceSignedItems(it)) }
                }
            }.toDeviceNameSpaces()
    }
}

fun Map<String, DeviceSignedItems>.toDeviceNameSpaces(): DeviceNameSpaces = DeviceNameSpaces(this)

@JvmInline
value class DeviceSignedItems(val items: NonEmptyList<DeviceSignedItem>) {
    constructor(first: DeviceSignedItem, vararg rest: DeviceSignedItem) : this(NonEmptyList(first, rest.toList()))

    init {
        val identifiers = items.map { it.identifier }
        require(identifiers.distinct().size == identifiers.size) { "DeviceSignedItems identifiers must be unique" }
    }

    fun toMapElement(): MapElement =
        buildMap {
            items.forEach { (identifier, value) -> put(MapKey(identifier), value) }
        }.toDataElement()

    fun toCbor(): ByteArray = waltIdCbor.encodeToByteArray(toMapElement())
    fun toCborHex(): String = waltIdCbor.encodeToHexString(toMapElement())
}

data class DeviceSignedItem(val identifier: String, val value: AnyDataElement)

@CborArray
@Serializable
data class SessionTranscript(
    @EncodeDefault val deviceEngagementBytes: ByteArray? = null,
    @EncodeDefault val eReaderKeyBytes: ByteArray? = null,
    @Required val handover: OpenID4VPHandover,
) {
    constructor(handover: OpenID4VPHandover) : this(deviceEngagementBytes = null, eReaderKeyBytes = null, handover = handover)

    init {
        require(null == deviceEngagementBytes) { "deviceEngagementBytes must be null" }
        require(null == eReaderKeyBytes) { "eReaderKeyBytes must be null" }
    }

    fun toCbor(): ByteArray = kotlinXSerializationCbor.encodeToByteArray(this)
    fun toCborHex(): String = kotlinXSerializationCbor.encodeToHexString(this)
    fun toListElement(): ListElement = waltIdCbor.decodeFromByteArray(toCbor())

    override fun equals(other: Any?): Boolean =
        other is SessionTranscript &&
            deviceEngagementBytes.contentEquals(other.deviceEngagementBytes) &&
            eReaderKeyBytes.contentEquals(other.eReaderKeyBytes) &&
            handover == other.handover

    override fun hashCode(): Int {
        var result = deviceEngagementBytes?.contentHashCode() ?: 0
        result = 31 * result + (eReaderKeyBytes?.contentHashCode() ?: 0)
        result = 31 * result + handover.hashCode()
        return result
    }
}

@CborArray
@Serializable
data class OpenID4VPHandover(
    @Required @EncodeDefault val identifier: String = IDENTIFIER,
    @Required @ByteString val openID4VPHandoverInfoHash: ByteArray,
) {
    init {
        require(IDENTIFIER == identifier) { "identifier must be '$IDENTIFIER'" }
    }

    fun toCbor(): ByteArray = kotlinXSerializationCbor.encodeToByteArray(this)
    fun toCborHex(): String = kotlinXSerializationCbor.encodeToHexString(this)

    override fun equals(other: Any?): Boolean =
        other is OpenID4VPHandover &&
            identifier == other.identifier &&
            openID4VPHandoverInfoHash.contentEquals(other.openID4VPHandoverInfoHash)

    override fun hashCode(): Int {
        var result = identifier.hashCode()
        result = 31 * result + openID4VPHandoverInfoHash.contentHashCode()
        return result
    }

    companion object {
        const val IDENTIFIER = "OpenID4VPHandover"

        operator fun invoke(
            sha256: (ByteArray) -> ByteArray = { MessageDigest.getInstance("SHA-256").digest(it) },
            clientId: VerifierId,
            nonce: Nonce,
            ephemeralEncryptionKey: JWK?,
            responseUri: URL,
        ): OpenID4VPHandover = invoke(sha256, OpenID4VPHandoverInfo(clientId, nonce, ephemeralEncryptionKey, responseUri))

        operator fun invoke(
            sha256: (ByteArray) -> ByteArray = { MessageDigest.getInstance("SHA-256").digest(it) },
            openID4VPHandoverInfo: OpenID4VPHandoverInfo,
        ): OpenID4VPHandover {
            val openID4VPHandoverInfoBytes = openID4VPHandoverInfo.toCbor()
            val openID4VPHandoverInfoHash = sha256(openID4VPHandoverInfoBytes)
            return OpenID4VPHandover(openID4VPHandoverInfoHash = openID4VPHandoverInfoHash)
        }
    }
}

@CborArray
@Serializable
data class OpenID4VPHandoverInfo(
    @Required val clientId: String,
    @Required val nonce: String,
    @EncodeDefault @ByteString val jwkThumbprint: ByteArray? = null,
    @Required val responseUri: String,
) {
    fun toCbor(): ByteArray = kotlinXSerializationCbor.encodeToByteArray(this)
    fun toCborHex(): String = kotlinXSerializationCbor.encodeToHexString(this)

    override fun equals(other: Any?): Boolean =
        other is OpenID4VPHandoverInfo &&
            clientId == other.clientId &&
            nonce == other.nonce &&
            jwkThumbprint.contentEquals(other.jwkThumbprint) &&
            responseUri == other.responseUri

    override fun hashCode(): Int {
        var result = clientId.hashCode()
        result = 31 * result + nonce.hashCode()
        result = 31 * result + (jwkThumbprint?.contentHashCode() ?: 0)
        result = 31 * result + responseUri.hashCode()
        return result
    }

    companion object {
        operator fun invoke(
            clientId: VerifierId,
            nonce: Nonce,
            ephemeralEncryptionKey: JWK? = null,
            responseUri: URL,
        ): OpenID4VPHandoverInfo = OpenID4VPHandoverInfo(
            clientId = clientId.clientId,
            nonce = nonce.value,
            jwkThumbprint = ephemeralEncryptionKey?.computeThumbprint()?.decode(),
            responseUri = responseUri.toExternalForm(),
        )
    }
}
