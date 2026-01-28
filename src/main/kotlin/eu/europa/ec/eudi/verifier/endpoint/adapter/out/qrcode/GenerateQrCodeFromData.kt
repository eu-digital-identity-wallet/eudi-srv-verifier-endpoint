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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.qrcode

import arrow.core.Either
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.client.j2se.MatrixToImageConfig
import com.google.zxing.client.j2se.MatrixToImageWriter
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.GenerateQrCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.Pixels
import java.io.ByteArrayOutputStream

val GenerateQrCodeFromData = GenerateQrCode { data, size ->
    Either.catch {
        val writer = QRCodeWriter()
        val matrix = writer.encode(
            data,
            BarcodeFormat.QR_CODE,
            size.width.toInt(),
            size.height.toInt(),
            mapOf(
                EncodeHintType.CHARACTER_SET to Charsets.UTF_8.name(),
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
            ),
        )
        ByteArrayOutputStream().use {
            MatrixToImageWriter.writeToStream(matrix, "PNG", it, MatrixToImageConfig())
            it.toByteArray()
        }
    }
}

private fun Pixels.toInt(): Int = size.toInt()
