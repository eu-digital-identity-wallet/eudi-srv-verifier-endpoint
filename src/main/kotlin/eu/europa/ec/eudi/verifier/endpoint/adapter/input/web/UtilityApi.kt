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

import arrow.core.raise.catch
import arrow.core.raise.effect
import arrow.core.raise.fold
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.verifier.endpoint.domain.AttestationClassifications
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.port.input.ProcessSdJwtVc
import eu.europa.ec.eudi.verifier.endpoint.port.input.ValidateMsoMdocDeviceResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.ValidateSdJwtVc
import eu.europa.ec.eudi.verifier.endpoint.port.input.toJson
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok
import kotlin.collections.filterNot
import kotlin.collections.firstOrNull

private val log = LoggerFactory.getLogger(UtilityApi::class.java)

internal class UtilityApi(
    private val validateMsoMdocDeviceResponse: ValidateMsoMdocDeviceResponse,
    private val validateSdJwtVc: ValidateSdJwtVc,
    private val processSdJwtVc: ProcessSdJwtVc,
    private val attestationClassifications: AttestationClassifications,
) {
    val route: RouterFunction<ServerResponse> =
        coRouter {
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

            GET(
                ATTESTATION_CLASSIFICATIONS_PATH,
                accept(APPLICATION_JSON),
                ::handleAttestationClassifications,
            )
        }

    private suspend fun handleValidateMsoMdocDeviceResponse(request: ServerRequest): ServerResponse =
        effect {
            val form = request.awaitFormData()
            val deviceResponse =
                form["device_response"]
                    ?.firstOrNull { it.isNotBlank() }
                    .let {
                        requireNotNull(it) { "device_response must be provided" }
                    }
            val issuerChain = form.issuerChain()
            validateMsoMdocDeviceResponse(deviceResponse = deviceResponse, issuerChain = issuerChain)
        }.fold(
            transform = { documents -> ok().json().bodyValueAndAwait(documents) },
            recover = { error -> badRequest().json().bodyValueAndAwait(error) },
        )

    private suspend fun handleValidateSdJwtVc(request: ServerRequest): ServerResponse =
        effect {
            val form = request.awaitFormData()
            val unverifiedSdJwtVc = form.unprocessedSdJwtVc()
            val nonce = form.nonce()
            val expectedAudience = form.expectedAudience()
            val issuerChain = form.issuerChain()
            validateSdJwtVc(unverifiedSdJwtVc, nonce, expectedAudience, issuerChain)
        }.fold(
            transform = { result ->
                val (reCreated, _) =
                    with(NimbusSdJwtOps) {
                        result.sdJwt.recreateClaimsAndDisclosuresPerClaim()
                    }
                ok().json().bodyValueAndAwait(reCreated)
            },
            recover = { error -> badRequest().json().bodyValueAndAwait(error.toJson()) },
        )

    private suspend fun handleProcessSdJwtVc(request: ServerRequest): ServerResponse =
        catch(
            block = {
                val form = request.awaitFormData()
                val unprocessedSdJwtVc = form.unprocessedSdJwtVc()
                processSdJwtVc(unprocessedSdJwtVc)
            },
            transform = { ok().json().bodyValueAndAwait(it) },
            catch = { error ->
                log.warn("Could not process SD-JWT VC payload.", error)
                badRequest().buildAndAwait()
            },
        )

    private suspend fun handleAttestationClassifications(request: ServerRequest): ServerResponse =
        ok().json().bodyValueAndAwait(attestationClassifications)

    companion object {
        const val VALIDATE_MSO_MDOC_DEVICE_RESPONSE_PATH = "/utilities/validations/msoMdoc/deviceResponse"
        const val VALIDATE_SD_JWT_VC_PATH = "/utilities/validations/sdJwtVc"
        const val PROCESS_SD_JWT_VC_PATH = "/utilities/process/sdJwtVc"
        const val ATTESTATION_CLASSIFICATIONS_PATH = "/utilities/attestationClassifications"
    }
}

private fun MultiValueMap<String, String>.unprocessedSdJwtVc(): String {
    val unprocessedSdJwtVc = this["sd_jwt_vc"]?.firstOrNull { it.isNotBlank() }
    return requireNotNull(unprocessedSdJwtVc) { "sd_jwt_vc must be provided" }
}

private fun MultiValueMap<String, String>.nonce(): Nonce {
    val nonce = this["nonce"]?.firstOrNull { it.isNotBlank() }?.let(::Nonce)
    return requireNotNull(nonce) { "nonce must be provided" }
}

private fun MultiValueMap<String, String>.expectedAudience(): String? = this["expected_audience"]?.firstOrNull { it.isNotBlank() }

private fun MultiValueMap<String, String>.deviceResponse(): String {
    val deviceResponse = this["device_response"]?.firstOrNull { it.isNotBlank() }
    return requireNotNull(deviceResponse) { "device_response must be provided" }
}

private fun MultiValueMap<String, String>.issuerChain(): String? = this["issuer_chain"]?.filterNot { it.isBlank() }?.firstOrNull()
