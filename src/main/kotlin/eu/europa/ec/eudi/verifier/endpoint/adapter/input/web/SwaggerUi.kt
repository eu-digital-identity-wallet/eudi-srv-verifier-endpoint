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

import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.renderAndAwait

private val log = LoggerFactory.getLogger(SwaggerUi::class.java)

/**
 * Web adapter for displaying the Swagger UI.
 *
 * @param publicResourcesBasePath base path for accessing public resources
 * @param webJarResourcesBasePath base path for accessing web jar resources
 * @property route the routes handled by this web adapter
 */
internal class SwaggerUi(
    private val publicResourcesBasePath: String,
    private val webJarResourcesBasePath: String,
) {
    val route: RouterFunction<ServerResponse> = coRouter {
        (GET("") or GET("/")) {
            log.info("Redirecting to {}", SWAGGER_UI)
            ServerResponse.status(HttpStatus.TEMPORARY_REDIRECT)
                .renderAndAwait("redirect:$SWAGGER_UI")
        }

        GET(SWAGGER_UI, contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML)) {
            log.info("Displaying Swagger UI")
            ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    name = "swagger-ui",
                    model = mapOf(
                        "publicResourcesBasePath" to publicResourcesBasePath,
                        "webJarResourcesBasePath" to webJarResourcesBasePath,
                        "openid4VpVersion" to OpenId4VPSpec.VERSION,
                    ),
                )
        }
    }

    companion object {
        const val SWAGGER_UI = "/swagger-ui"
    }
}
