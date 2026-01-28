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
package eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode

import arrow.core.Either

typealias PNGImage = ByteArray

@JvmInline
value class Pixels(val size: UInt) {
    init {
        require(size > 0u)
    }

    companion object {
        val Int.pixels: Pixels
            get() = Pixels(toUInt())

        val UInt.pixels: Pixels
            get() = Pixels(this)
    }
}

data class Dimensions(val width: Pixels, val height: Pixels)

infix fun Pixels.by(height: Pixels): Dimensions = Dimensions(this, height)

fun interface GenerateQrCode {

    /**
     * Generates a [PNGImage] that contains a QR Code with the provided [data].
     */
    suspend operator fun invoke(data: String, size: Dimensions): Either<Throwable, PNGImage>
}
