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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal object SignedJWTSerializer : KSerializer<SignedJWT> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("SignedJWT", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: SignedJWT,
    ) {
        encoder.encodeString(value.serialize())
    }

    override fun deserialize(decoder: Decoder): SignedJWT {
        val value = decoder.decodeString()
        return SignedJWT.parse(value)
    }
}
