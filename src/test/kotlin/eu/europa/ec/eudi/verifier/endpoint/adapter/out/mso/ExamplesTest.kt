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

import arrow.core.getOrElse
import cbor.Cbor
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.issuersigned.IssuerSigned
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.toKotlinTimeZone
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import java.time.ZonedDateTime
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.fail
import kotlin.time.toKotlinInstant

/**
 * This is from
 *
 * https://github.com/walt-id/waltid-identity/tree/main/waltid-libraries/credentials/waltid-mdoc-credentials
 *
 * It contains a mso_mdoc (in HEX), that was issued at "2023-08-02T16:22:19.252519705Z"
 */
val waltIdExample =
    """
       a267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564a26a6e616d65537061636573a1716f72672e69736f2e31383031332e352e3183d8185852a4686469676573744944006672616e646f6d501d5a0b315468e8e741c7d0fbf2267ea671656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756563446f65d8185852a4686469676573744944016672616e646f6d505a212f6b1afa24c80fdf756859b6e0e571656c656d656e744964656e7469666965726a676976656e5f6e616d656c656c656d656e7456616c7565644a6f686ed818585ba4686469676573744944026672616e646f6d50595961fbb375b6330e60016e33e3caa471656c656d656e744964656e7469666965726a62697274685f646174656c656c656d656e7456616c7565d903ec6a313939302d30312d31356a697373756572417574688443a10126a1182159014b308201473081eea00302010202085851077f1cb3d768300a06082a8648ce3d04030230173115301306035504030c0c4d444f432054657374204341301e170d3233303830323136323231395a170d3233303830333136323231395a301b3119301706035504030c104d444f432054657374204973737565723059301306072a8648ce3d020106082a8648ce3d030107034200045f1c8ff18cb0b57445f16eec0584fcf69a6829d955a3284fa42e4d091f6da49196f5b9c917a39ecbf2bf7cdd06597169433c1d9cde0a9ee9772bd29b12fcb775a320301e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06082a8648ce3d0403020348003045022075e093d7e7128060f42ca9a675b97c6312c46cbecd23afdbe8619e964eab37e2022100d9b522c7b80f93dd978a955d0ffdb5f64dc40fa9aa1aa6e10902b306821d13ed5901c3d8185901bea66776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473a1716f72672e69736f2e31383031332e352e31a3005820534172b2a1e4082a7644b42299271711891b29adfd50b10a18524e8827d308ae0158204892baa76842258533af9eac579397d024cbff8536afda2da2b9c62a4b30704102582002fc10a9f125740b67e29264cd03ba4994a56f3377c62344d092c614cc18bdb06d6465766963654b6579496e666fa1696465766963654b6579a401022001215820f2862d595d95758368138cb90e3c0df01a432ce1f569ea0d26e80351cf6d0425225820fd20afda5943e95dbd6c679fe1ffb425ec92a65bfcfa2c2c1882669d3bed737267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa3667369676e6564c0781e323032332d30382d30325431363a32323a31392e3235323531363736395a6976616c696446726f6dc0781e323032332d30382d30325431363a32323a31392e3235323531393730355a6a76616c6964556e74696cc0781e323032342d30382d30315431363a32323a31392e3235323532303435375a5840a59ce0142b6943b26da7a79a71167ab459702d4231a46990d573445034abee6fe275582686a71ab37fed5a6a0819c740bb79f6e24e7786022db07c7469cb1d09
    """.trimIndent()

/**
 * This is from
 * https://www.authlete.com/developers/oid4vci/#425-mdoc
 *
 * It contains an mDL (IssuerSigned) in base64 url-encoded
 */
val authleteExample =
    """
        ompuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYjYGFhbpGhkaWdlc3RJRAFmcmFuZG9tUEJDfxiBFQGMwsBY7jE6mkdxZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAyNC0wNi0wNdgYWFykaGRpZ2VzdElEAmZyYW5kb21QuWRGth4zjRXOJN_iGNTy0nFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAyNS0wNi0wNdgYWFqkaGRpZ2VzdElEA2ZyYW5kb21Q7Zx7xYZtB0D02nL-x0UGFXFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVrU2lsdmVyc3RvbmXYGFhSpGhkaWdlc3RJRARmcmFuZG9tUPMV5L8B03Uuj0GRMFZvWpJxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVkSW5nYdgYWFukaGRpZ2VzdElEBWZyYW5kb21Q3fLHe4K4bUMJDFsSYKJ513FlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoxOTkxLTExLTA22BhYVaRoZGlnZXN0SUQGZnJhbmRvbVDIzuaMNAe24KBZ3QQpP5o8cWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWxlbGVtZW50VmFsdWViVVPYGFhbpGhkaWdlc3RJRAdmcmFuZG9tUJV-wSoCvKEqVh_g3844LmdxZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVybGVsZW1lbnRWYWx1ZWgxMjM0NTY3ONgYWKKkaGRpZ2VzdElECGZyYW5kb21QZHMJeAleAPyXtFA-TiWBD3FlbGVtZW50SWRlbnRpZmllcnJkcml2aW5nX3ByaXZpbGVnZXNsZWxlbWVudFZhbHVlgaN1dmVoaWNsZV9jYXRlZ29yeV9jb2RlYUFqaXNzdWVfZGF0ZdkD7GoyMDIzLTAxLTAxa2V4cGlyeV9kYXRl2QPsajIwNDMtMDEtMDFqaXNzdWVyQXV0aIRDoQEmoRghWQFhMIIBXTCCAQSgAwIBAgIGAYyR2cIZMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMK0oxRndKUDg3QzYtUU5fV1NJT21KQVFjNm41Q1FfYlpkYUZKNUdEblcxUmswHhcNMjMxMjIyMTQwNjU2WhcNMjQxMDE3MTQwNjU2WjA2MTQwMgYDVQQDDCtKMUZ3SlA4N0M2LVFOX1dTSU9tSkFRYzZuNUNRX2JaZGFGSjVHRG5XMVJrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAopVeboJpYRycw1YKkkROXfCpKEKl9Y1YPFhOGj4xTg2UOunxTxSIVkT94qFVIuu1hkEoE2NxelZo3-yTFUODDAKBggqhkjOPQQDAgNHADBEAiBnFjScBcvERleLjMCu5NbxJKkNsa_gQhkXTfDmbq-T3gIgVazbsVdQvZgluc9nJYQxWlzXT9i6f-wgUKx0KCYbj3BZArLYGFkCraZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMagBWCBtyGKRLbYNCtXpIqSixji4RYcXb4Vf7IDoQta4QfRWsAJYIJVrdxQWwcfqiFi75y5R3Saj8YpA8miZxmeoQL_JtB5-A1ggnoXpxMgIsgiIr8HlJ9JzfalESFVLgFxmES9SqSIsIG0EWCD-4Mo98S8qg8SJ8R-PMO7oCHW3wbdCfU8GGS0nG7VahwVYIE9yvCITC8M8p7-m2M4A5MwokXN3oS97uLkhk2AIj6GRBlgg8IaPGI_7Tp2rf2fLhEq0dDzm71FmTZUPc16BdJsCDgkHWCAKnWjJaTmwvgq1Yon8cLwPaPS1-lOEVASldrxYkeKLcwhYIEXVTVGxIhP9R64iPFGseCD_adyfhYZdCw-eOO8ckRjzbWRldmljZUtleUluZm-iaWRldmljZUtleaYBAgJYKzFlNUFZOUV5QjAxWG5VemE2THBKemswMm42WV9BbW1uU2IwRkJlTlZWclUDJiABIVggPSxQrD2zl0_mXcAqz1mgqSeBoBhnmx2yxBEprBY8F20iWCDFXx9uLUVKixS6ct64s24uQmKqZjpMqIye6v4afbBHXXFrZXlBdXRob3JpemF0aW9uc6FqbmFtZVNwYWNlc4Fxb3JnLmlzby4xODAxMy41LjFnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMDYtMDVUMDM6MzU6MTRaaXZhbGlkRnJvbcB0MjAyNC0wNi0wNVQwMzozNToxNFpqdmFsaWRVbnRpbMB0MjAyNS0wNi0wNVQwMzozNToxNFpYQAs0d0MAErcaA1auodhHxivYcqiSXdQW9KtG9HpZoxo_oEPfkf7_dRQm_Z-ffhZn2qbLTc2Op3x0a1R-gif9Mtg
    """.trimIndent()

class ExamplesTest {

    @Test
    fun `waltId example is valid, skipping x5c checks`() = runTest {
        val issuedAt = ZonedDateTime.parse("2023-08-02T16:22:19.252519705Z")

        val documentValidator = DocumentValidator(
            clock = Clock.fixed(issuedAt.toInstant().toKotlinInstant(), issuedAt.zone.toKotlinTimeZone()),
            provideTrustSource = ProvideTrustSource.Ignored,
            statusListTokenValidator = null,
        )
        val document = MDoc.fromCBORHex(waltIdExample)
        documentValidator.ensureValid(document).getOrElse { fail(it.toString()) }
    }

    @OptIn(ExperimentalEncodingApi::class, ExperimentalSerializationApi::class)
    @Test
    fun `athlete example is valid, skipping x5c checks`() = runTest {
        fun issuerSigned(): IssuerSigned {
            val base64Dec = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)
            val cbor = base64Dec.decode(authleteExample)
            return Cbor.decodeFromByteArray<IssuerSigned>(cbor)
        }

        val trustSources = ProvideTrustSource.Ignored
        val issuedAt = ZonedDateTime.parse("2024-08-02T16:22:19.252519705Z")
        val document = issuerSigned().asMDocWithDocType("org.iso.18013.5.1.mDL")
        val documentValidator = DocumentValidator(
            clock = Clock.fixed(issuedAt.toInstant().toKotlinInstant(), issuedAt.zone.toKotlinTimeZone()),
            provideTrustSource = trustSources::invoke,
            statusListTokenValidator = null,
        )
        documentValidator.ensureValid(document).getOrElse { fail(it.toString()) }
    }
}

private fun IssuerSigned.asMDocWithDocType(docType: String) =
    MDoc(
        docType = docType.toDataElement(),
        issuerSigned = this,
        deviceSigned = null,
    )
