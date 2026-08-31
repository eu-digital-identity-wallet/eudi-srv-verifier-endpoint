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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import kotlin.test.Test

/**
 * A required form field that is not supplied is a client error on every utility endpoint.
 */
@VerifierApplicationTest
internal class UtilityApiTest {
    @Autowired
    private lateinit var client: WebTestClient

    private fun postFormExpectingBadRequest(
        path: String,
        vararg fields: Pair<String, String>,
    ) {
        val form = LinkedMultiValueMap<String, String>()
        fields.forEach { (name, value) -> form.add(name, value) }
        client
            .post()
            .uri(path)
            .contentType(APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(form))
            .exchange()
            .expectStatus()
            .isBadRequest
    }

    @Test
    fun `when nonce is not included in sd-jwt-vc validation, validation fails`() {
        postFormExpectingBadRequest(UtilityApi.VALIDATE_SD_JWT_VC_PATH, "sd_jwt_vc" to SD_JWT_VC)
    }

    @Test
    fun `when sd-jwt-vc is not included in sd-jwt-vc validation, validation fails`() {
        postFormExpectingBadRequest(UtilityApi.VALIDATE_SD_JWT_VC_PATH, "nonce" to "nonce")
    }

    @Test
    fun `when device response is not included in mso mdoc validation, validation fails`() {
        postFormExpectingBadRequest(UtilityApi.VALIDATE_MSO_MDOC_DEVICE_RESPONSE_PATH)
    }

    @Test
    fun `when sd-jwt-vc is not included in sd-jwt-vc processing, processing fails`() {
        postFormExpectingBadRequest(UtilityApi.PROCESS_SD_JWT_VC_PATH)
    }

    companion object {
        private const val SD_JWT_VC = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.signature~"
    }
}
