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

import com.nimbusds.jose.jwk.JWK
import kotlin.test.Test
import kotlin.test.assertEquals

class DeviceAuthenticationTest {
    private val ephemeralEncryptionKey =
        JWK.parse(
            """
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                  "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
                  "use": "enc",
                  "alg": "ECDH-ES",
                  "kid": "1"
                }
            """.trimIndent(),
        )
    private val clientId = "x509_san_dns:example.com"
    private val nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
    private val responseUri = "https://example.com/response"

    @Test
    fun `OpenID4VPHandoverInfo serialization test`() {
        val expectedHex =
            """
                847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767
                426b786a7831726463397564527276654b7653734a4971383061766c58654c486847
                7771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6
                bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365
            """.trimIndent().replace("\n", "")

        val openID4VPHandoverInfo = OpenID4VPHandoverInfo(
            clientId = clientId,
            nonce = nonce,
            jwkThumbprint = ephemeralEncryptionKey.computeThumbprint().decode(),
            responseUri = responseUri,
        )
        val actualHex = openID4VPHandoverInfo.toCborHex()

        assertEquals(expectedHex, actualHex)
    }

    @Test
    fun `OpenID4VPHandover serialization test`() {
        val expectedHex =
            """
                82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494c
                efdd9d95240d254b046b11b68013722aad38ac
            """.trimIndent().replace("\n", "")

        val openID4VPHandover = OpenID4VPHandover(
            openID4VPHandoverInfo = OpenID4VPHandoverInfo(
                clientId = clientId,
                nonce = nonce,
                jwkThumbprint = ephemeralEncryptionKey.computeThumbprint().decode(),
                responseUri = responseUri,
            ),
        )
        val actualHex = openID4VPHandover.toCborHex()

        assertEquals(expectedHex, actualHex)
    }

    @Test
    fun `SessionTranscript serialization test`() {
        val expectedHex =
            """
                83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e
                ed494cefdd9d95240d254b046b11b68013722aad38ac
            """.trimIndent().replace("\n", "")

        val sessionTranscript = SessionTranscript(
            handover = OpenID4VPHandover(
                openID4VPHandoverInfo = OpenID4VPHandoverInfo(
                    clientId = clientId,
                    nonce = nonce,
                    jwkThumbprint = ephemeralEncryptionKey.computeThumbprint().decode(),
                    responseUri = responseUri,
                ),
            ),
        )

        listOf(sessionTranscript.toCborHex(), sessionTranscript.toListElement().toCBORHex())
            .forEach { actualHex -> assertEquals(expectedHex, actualHex) }
    }
}
