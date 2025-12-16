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

import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.EncodedCBORElement
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mso.MSO
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.io.encoding.Base64
import cbor.Cbor as WaltIdCbor
import kotlinx.serialization.cbor.Cbor as KotlinXSerializationCbor

val waltIdCbor: WaltIdCbor by lazy {
    WaltIdCbor(WaltIdCbor.Default) {
        ignoreUnknownKeys = true
    }
}

val kotlinXSerializationCbor: KotlinXSerializationCbor by lazy {
    KotlinXSerializationCbor(KotlinXSerializationCbor.CoseCompliant) {
        ignoreUnknownKeys = true
    }
}

val base64UrlNoPadding: Base64 by lazy {
    Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
}

/**
 * Decodes a [DeviceResponse] from a Base64 URL encoded CBOR value.
 *
 * Unknown properties are ignored.
 */
fun DeviceResponse.Companion.decodeFromCborBase64Url(value: String): DeviceResponse {
    val decoded = base64UrlNoPadding.decode(value)
    return waltIdCbor.decodeFromByteArray(decoded)
}

/**
 * Decodes the [MSO] of this [MDoc].
 *
 * Unknown properties are ignored.
 *
 * **This is a hack to circumvent a `walt.id` library limitation. Currently, it does not support the `status` property in [MSO].**
 */
fun MDoc.decodeMso() {
    if (_mso == null) {
        _mso = issuerSigned.issuerAuth?.payload?.let { data ->
            val encoded = waltIdCbor.decodeFromByteArray<EncodedCBORElement>(data)
            waltIdCbor.decodeFromByteArray<MSO>(encoded.value)
        }
    }
}

inline fun <reified T> DataElement.decodeAs(): T = waltIdCbor.decodeFromByteArray(waltIdCbor.encodeToByteArray(this))
