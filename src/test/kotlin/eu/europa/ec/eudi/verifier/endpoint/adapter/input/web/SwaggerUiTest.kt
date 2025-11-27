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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient
import org.springframework.core.env.Environment
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@VerifierApplicationTest
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString())
internal class SwaggerUiTest {
    private val log: Logger = LoggerFactory.getLogger(SwaggerUiTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    @Autowired
    private lateinit var environment: Environment

    @Test
    fun `confirm Swagger UI is accessible`() {
        val responseBody =
            client.get()
                .uri("/swagger-ui")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.TEXT_HTML)
                .expectBody<String>()
                .returnResult()
                .responseBody
                ?.also {
                    log.info("Swagger UI: $it")
                }

        assertNotNull(responseBody, "No body returned for Swagger UI")

        val publicResourcesBasePath = environment.getRequiredProperty("spring.webflux.static-path-pattern").removeSuffix("/**")
        val webJarResourcesBasePath = environment.getRequiredProperty("spring.webflux.webjars-path-pattern").removeSuffix("/**")
        listOf(
            "$webJarResourcesBasePath/swagger-ui/swagger-ui.css",
            "$webJarResourcesBasePath/swagger-ui/favicon-32x32.png",
            "$webJarResourcesBasePath/swagger-ui/favicon-16x16.png",
            "$webJarResourcesBasePath/swagger-ui/swagger-ui-bundle.js",
            "$webJarResourcesBasePath/swagger-ui/swagger-ui-standalone-preset.js",
            "$publicResourcesBasePath/openapi.json",
        ).forEach { assertTrue("Missing expected element: '$it' in Swagger UI") { responseBody.contains(it) } }
    }
}
