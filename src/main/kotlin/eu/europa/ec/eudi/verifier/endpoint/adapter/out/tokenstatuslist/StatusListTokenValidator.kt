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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import arrow.core.Either
import arrow.core.raise.catch
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.right
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.statium.GetStatus
import eu.europa.ec.eudi.statium.GetStatusListToken
import eu.europa.ec.eudi.statium.Status
import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.tokenStatusListReference
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.statusReference
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock.Companion.asKotlinClock
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import id.walt.mdoc.doc.MDoc
import io.ktor.client.*
import kotlin.time.Duration.Companion.seconds

sealed interface StatusValidationError {
    /**
     * Indicate the Status of a Document is not Valid. (i.e. most likely has been Revoked, or Suspended, etc...)
     */
    data class StatusNotValid(
        val status: Status,
    ) : StatusValidationError {
        init {
            require(Status.Valid != status)
        }
    }

    /**
     * Indicates the Status List Token could not be checked
     */
    class StatusCheckException(
        message: String,
        cause: Throwable,
    ) : Exception(message, cause),
        StatusValidationError
}

class StatusListTokenValidator(
    private val httpClient: HttpClient,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) {
    suspend fun validate(
        sdJwtVc: SdJwtAndKbJwt<SignedJWT>,
        transactionId: TransactionId?,
    ): Either<StatusValidationError, Status.Valid> =
        sdJwtVc
            .statusReference()
            ?.validate(transactionId, StatusListTokenFormat.JWT)
            ?: Status.Valid.right()

    suspend fun validate(
        mdoc: MDoc,
        transactionId: TransactionId?,
    ): Either<StatusValidationError, Status.Valid> =
        mdoc.issuerSigned.issuerAuth
            ?.tokenStatusListReference()
            ?.validate(transactionId, StatusListTokenFormat.CWT)
            ?: Status.Valid.right()

    private suspend fun StatusReference.validate(
        transactionId: TransactionId?,
        format: StatusListTokenFormat,
    ): Either<StatusValidationError, Status.Valid> =
        either {
            val currentStatus =
                catch({
                    with(getStatus(format)) { currentStatus().getOrThrow() }
                }) { error ->
                    transactionId?.let { logStatusCheckFailed(it, this@validate, error) }
                    raise(StatusValidationError.StatusCheckException("Attestation status check failed, ${error.message}", error))
                }

            ensure(currentStatus == Status.Valid) { StatusValidationError.StatusNotValid(currentStatus) }
            transactionId?.let { logStatusCheckSuccess(it, this@validate) }
            Status.Valid
        }

    private fun getStatus(format: StatusListTokenFormat): GetStatus {
        val getStatusListToken =
            when (format) {
                StatusListTokenFormat.JWT -> {
                    GetStatusListToken.usingJwt(
                        clock = clock.asKotlinClock(),
                        httpClient = httpClient,
                        verifyStatusListTokenSignature = { _, _ -> Result.success(Unit) },
                        allowedClockSkew = 15.seconds,
                    )
                }

                StatusListTokenFormat.CWT -> {
                    GetStatusListToken.usingCwt(
                        clock = clock.asKotlinClock(),
                        httpClient = httpClient,
                        verifyStatusListTokenSignature = { _, _ -> Result.success(Unit) },
                        allowedClockSkew = 15.seconds,
                    )
                }
            }
        return GetStatus(getStatusListToken)
    }

    private suspend fun logStatusCheckSuccess(
        transactionId: TransactionId,
        statusReference: StatusReference,
    ) {
        val event = PresentationEvent.AttestationStatusCheckSuccessful(transactionId, clock.now(), statusReference)
        publishPresentationEvent(event)
    }

    private suspend fun logStatusCheckFailed(
        transactionId: TransactionId,
        statusReference: StatusReference,
        error: Throwable,
    ) {
        val event = PresentationEvent.AttestationStatusCheckFailed(transactionId, clock.now(), statusReference, error.message)
        publishPresentationEvent(event)
    }
}

private enum class StatusListTokenFormat {
    JWT,
    CWT,
}
