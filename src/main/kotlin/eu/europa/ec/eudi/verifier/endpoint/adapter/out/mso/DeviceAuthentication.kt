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
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mdocauth.DeviceAuthentication
import kotlinx.serialization.*
import java.net.URL
import java.security.MessageDigest
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.cbor as myCbor

operator fun DeviceAuthentication.Companion.invoke(
    sessionTranscript: SessionTranscript,
    docType: String,
    deviceNameSpaces: DeviceNameSpaces,
): DeviceAuthentication = DeviceAuthentication(
    sessionTranscript = sessionTranscript.toListElement(),
    docType = docType,
    deviceNameSpaces = deviceNameSpaces.toEncodedCborElement(),
)

typealias NameSpace = String

@JvmInline
value class DeviceNameSpaces(val nameSpaces: Map<NameSpace, DeviceSignedItems>) {
    fun toMapElement(): MapElement =
        buildMap {
            nameSpaces.forEach { (nameSpace, deviceSignedItems) -> put(MapKey(nameSpace), deviceSignedItems.toMapElement()) }
        }.toDataElement()
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toMapElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toMapElement())
    fun toEncodedCborElement(cbor: Cbor = myCbor): EncodedCBORElement = EncodedCBORElement(toCbor(cbor))

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

fun Map<NameSpace, DeviceSignedItems>.toDeviceNameSpaces(): DeviceNameSpaces = DeviceNameSpaces(this)

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
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toMapElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toMapElement())
}

typealias DataElementIdentifier = String

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
            verifierId: VerifierId,
            nonce: Nonce,
            ephemeralEncryptionKey: JWK?,
            responseUri: URL,
        ): OpenID4VPHandover = invoke(sha256, OpenID4VPHandoverInfo(verifierId, nonce, ephemeralEncryptionKey, responseUri))

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

data class OpenID4VPHandoverInfo(
    val clientId: String,
    val nonce: String,
    val ephemeralEncryptionKey: JWK? = null,
    val responseUri: URL,
) {
    constructor(
        verifierId: VerifierId,
        nonce: Nonce,
        ephemeralEncryptionKey: JWK?,
        responseUri: URL,
    ) : this(
        clientId = verifierId.clientId,
        nonce = nonce.value,
        ephemeralEncryptionKey = ephemeralEncryptionKey,
        responseUri = responseUri,
    )

    init {
        if (null != ephemeralEncryptionKey) {
            require(!ephemeralEncryptionKey.isPrivate) { "ephemeralEncryptionKey cannot be private" }
        }
    }

    fun toListElement(): ListElement = listOf(
        clientId.toDataElement(),
        nonce.toDataElement(),
        ephemeralEncryptionKey?.computeThumbprint()?.decode()?.toDataElement() ?: NullElement(),
        responseUri.toExternalForm().toDataElement(),
    ).toDataElement()
    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toListElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toListElement())
}
