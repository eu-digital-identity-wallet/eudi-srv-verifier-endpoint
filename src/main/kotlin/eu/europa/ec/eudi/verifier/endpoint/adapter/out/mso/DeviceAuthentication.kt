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
import cbor.Cbor
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import id.walt.mdoc.dataelement.*
import kotlinx.serialization.*
import java.net.URL
import java.security.MessageDigest
import kotlin.collections.component1
import kotlin.collections.component2
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.cbor as myCbor

@JvmInline
value class DeviceNameSpaces(val nameSpaces: Map<NameSpace, DeviceSignedItems>) : Map<NameSpace, DeviceSignedItems> by nameSpaces {
    fun toMapElement(): MapElement =
        buildMap {
            nameSpaces.forEach { (nameSpace, deviceSignedItems) -> put(MapKey(nameSpace), deviceSignedItems.toMapElement()) }
        }.toDataElement()
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toMapElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toMapElement())
    fun toEncodedCborElement(cbor: Cbor = myCbor): EncodedCBORElement = EncodedCBORElement(toCbor(cbor))

    companion object {
        fun fromMapElement(element: MapElement): DeviceNameSpaces =
            buildMap {
                element.value.forEach {
                        (nameSpace, deviceSignedItems) ->
                    put(nameSpace.str, DeviceSignedItems.fromMapElement(deviceSignedItems as MapElement))
                }
            }.let { DeviceNameSpaces(it) }

        fun fromEncodedCborElement(element: EncodedCBORElement, cbor: Cbor = myCbor): DeviceNameSpaces =
            fromMapElement(cbor.decodeFromByteArray<MapElement>(element.value))
    }
}

@JvmInline
value class DeviceSignedItems(val items: NonEmptyList<DeviceSignedItem>) : List<DeviceSignedItem> by items {
    init {
        val identifiers = items.map { it.identifier }
        require(identifiers.distinct().size == identifiers.size) { "DeviceSignedItems identifiers must be unique" }
    }

    fun toMapElement(): MapElement =
        buildMap {
            items.forEach { (identifier, value) -> put(MapKey(identifier), value) }
        }.toDataElement()
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toMapElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toMapElement())

    companion object {
        fun fromMapElement(element: MapElement): DeviceSignedItems {
            val deviceSignedItems = element.value.map {
                    (identifier, value) ->
                DeviceSignedItem(identifier.str, value)
            }.toNonEmptyListOrNull()
            return DeviceSignedItems(checkNotNull(deviceSignedItems))
        }
    }
}

data class DeviceSignedItem(val identifier: DataElementIdentifier, val value: AnyDataElement)

@JvmInline
value class SessionTranscript(val handover: OpenID4VPHandover) {
    fun toListElement(): ListElement = listOf(
        NullElement(),
        NullElement(),
        handover.toListElement(),
    ).toDataElement()
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toListElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toListElement())
}

@JvmInline
value class OpenID4VPHandover(val openID4VPHandoverInfoHash: ByteArray) {
    fun toListElement(): ListElement = listOf(
        IDENTIFIER.toDataElement(),
        openID4VPHandoverInfoHash.toDataElement(),
    ).toDataElement()
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toListElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toListElement())

    companion object {
        const val IDENTIFIER = "OpenID4VPHandover"

        operator fun invoke(
            sha256: (ByteArray) -> ByteArray = { MessageDigest.getInstance("SHA-256").digest(it) },
            cbor: Cbor = myCbor,
            verifierId: VerifierId,
            nonce: Nonce,
            ephemeralEncryptionKey: JWK?,
            responseUri: URL,
        ): OpenID4VPHandover = invoke(sha256, cbor, OpenID4VPHandoverInfo(verifierId, nonce, ephemeralEncryptionKey, responseUri))

        operator fun invoke(
            sha256: (ByteArray) -> ByteArray = { MessageDigest.getInstance("SHA-256").digest(it) },
            cbor: Cbor = myCbor,
            openID4VPHandoverInfo: OpenID4VPHandoverInfo,
        ): OpenID4VPHandover {
            val openID4VPHandoverInfoBytes = openID4VPHandoverInfo.toCbor(cbor)
            val openID4VPHandoverInfoHash = sha256(openID4VPHandoverInfoBytes)
            return OpenID4VPHandover(openID4VPHandoverInfoHash = openID4VPHandoverInfoHash)
        }
    }
}

data class OpenID4VPHandoverInfo(
    val clientId: String,
    val nonce: String,
    val jwkThumbprint: ByteArray? = null,
    val responseUri: String,
) {
    constructor(
        verifierId: VerifierId,
        nonce: Nonce,
        jwk: JWK?,
        responseUri: URL,
    ) : this(
        clientId = verifierId.clientId,
        nonce = nonce.value,
        jwkThumbprint = jwk?.computeThumbprint()?.decode(),
        responseUri = responseUri.toExternalForm(),
    )

    fun toListElement(): ListElement = listOf(
        clientId.toDataElement(),
        nonce.toDataElement(),
        jwkThumbprint?.toDataElement() ?: NullElement(),
        responseUri.toDataElement(),
    ).toDataElement()
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toListElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toListElement())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as OpenID4VPHandoverInfo

        if (clientId != other.clientId) return false
        if (nonce != other.nonce) return false
        if (!jwkThumbprint.contentEquals(other.jwkThumbprint)) return false
        if (responseUri != other.responseUri) return false

        return true
    }

    override fun hashCode(): Int {
        var result = clientId.hashCode()
        result = 31 * result + nonce.hashCode()
        result = 31 * result + (jwkThumbprint?.contentHashCode() ?: 0)
        result = 31 * result + responseUri.hashCode()
        return result
    }
}
