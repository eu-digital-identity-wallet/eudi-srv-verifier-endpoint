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

import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok
import kotlin.collections.firstOrNull

private val log = LoggerFactory.getLogger(UtilityApi::class.java)

internal class UtilityApi(
    private val validateMsoMdocDeviceResponse: ValidateMsoMdocDeviceResponse,
    private val validateSdJwtVc: ValidateSdJwtVc,
    private val processSdJwtVc: ProcessSdJwtVc,
) {
    val route: RouterFunction<ServerResponse> = coRouter {
        POST(
            VALIDATE_MSO_MDOC_DEVICE_RESPONSE_PATH,
            contentType(APPLICATION_FORM_URLENCODED) and accept(APPLICATION_JSON),
            ::handleValidateMsoMdocDeviceResponse,
        )

        POST(
            VALIDATE_SD_JWT_VC_PATH,
            contentType(APPLICATION_FORM_URLENCODED) and accept(APPLICATION_JSON),
            ::handleValidateSdJwtVc,
        )

        POST(
            PROCESS_SD_JWT_VC_PATH,
            contentType(APPLICATION_FORM_URLENCODED) and accept(APPLICATION_JSON),
            ::handleProcessSdJwtVc,
        )
    }

    private suspend fun handleValidateMsoMdocDeviceResponse(request: ServerRequest): ServerResponse {
        val form = request.awaitFormData()
        val deviceResponse = form["device_response"]
            ?.firstOrNull { it.isNotBlank() }
            .let {
                requireNotNull(it) { "device_response must be provided" }
            }
        val issuerChain = form["issuer_chain"]?.filterNot { it.isNullOrBlank() }?.firstOrNull()

        return when (val result = validateMsoMdocDeviceResponse(deviceResponse = deviceResponse, issuerChain = issuerChain)) {
            is DeviceResponseValidationResult.Valid ->
                ok().json()
                    .bodyValueAndAwait(result.documents)

            is DeviceResponseValidationResult.Invalid ->
                badRequest().json()
                    .bodyValueAndAwait(result.error)
        }
    }

    private suspend fun handleValidateSdJwtVc(request: ServerRequest): ServerResponse {
        val form = request.awaitFormData()
        val unverifiedSdJwtVc = form["sd_jwt_vc"]
            ?.firstOrNull { it.isNotBlank() }
            .let {
                requireNotNull(it) { "sd_jwt_vc must be provided" }
            }
        val nonce = form["nonce"]
            ?.firstOrNull { it.isNotBlank() }
            .let {
                requireNotNull(it) { "nonce must be provided" }
                Nonce(it)
            }
        val issuerChain = form["issuer_chain"]?.filterNot { it.isNullOrBlank() }?.firstOrNull()

        return when (val result = validateSdJwtVc(unverifiedSdJwtVc, nonce, issuerChain)) {
            is SdJwtVcValidationResult.Valid -> {
                val reCreated = with(NimbusSdJwtOps) {
                    result.payload.sdJwt.recreateClaimsAndDisclosuresPerClaim().first
                }
                ok().json().bodyValueAndAwait(reCreated)
            }
            is SdJwtVcValidationResult.Invalid -> badRequest().json().bodyValueAndAwait(result.toJson())
        }
    }

    private suspend fun handleProcessSdJwtVc(request: ServerRequest): ServerResponse {
        val form = request.awaitFormData()
        val unprocessedSdJwtVc = form["sd_jwt_vc"]
            ?.firstOrNull { it.isNotBlank() }
            .let {
                requireNotNull(it) { "sd_jwt_vc must be provided" }
            }

        return processSdJwtVc(unprocessedSdJwtVc)
            .fold(
                ifLeft = { error ->
                    log.warn("Could not process SD-JWT VC payload.", error)
                    badRequest().buildAndAwait()
                },
                ifRight = { ok().json().bodyValueAndAwait(it) },
            )
    }

    companion object {
        const val VALIDATE_MSO_MDOC_DEVICE_RESPONSE_PATH = "/utilities/validations/msoMdoc/deviceResponse"
        const val VALIDATE_SD_JWT_VC_PATH = "/utilities/validations/sdJwtVc"
        const val PROCESS_SD_JWT_VC_PATH = "/utilities/process/sdJwtVc"
    }
}
