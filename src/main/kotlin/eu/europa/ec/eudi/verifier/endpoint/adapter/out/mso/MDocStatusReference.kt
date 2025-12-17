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

import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.statium.TokenStatusListSpec
import id.walt.mdoc.cose.COSESign1
import id.walt.mdoc.dataelement.EncodedCBORElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import kotlinx.serialization.decodeFromByteArray

inline fun <reified T : Any> COSESign1.decodePayload(): T? =
    payload?.let {
        val encoded = cbor.decodeFromByteArray<EncodedCBORElement>(it)
        cbor.decodeFromByteArray<T>(encoded.value)
    }

fun COSESign1.tokenStatusListReference(): StatusReference? =
    runCatching {
        decodePayload<MapElement>()
            ?.value[MapKey(TokenStatusListSpec.STATUS)]
            ?.let { it as MapElement }
            ?.value[MapKey(TokenStatusListSpec.STATUS_LIST)]
            ?.decodeAs<StatusReference>()
    }.getOrNull()
