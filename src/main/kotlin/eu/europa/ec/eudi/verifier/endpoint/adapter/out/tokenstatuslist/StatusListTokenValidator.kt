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

import arrow.core.raise.catch
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

data class StatusCheckException(val reason: String, val causedBy: Throwable) : Exception(reason, causedBy)

class StatusListTokenValidator(
    private val httpClient: HttpClient,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) {

    suspend fun validate(sdJwtVc: SdJwtAndKbJwt<SignedJWT>, transactionId: TransactionId?) =
        sdJwtVc.statusReference()?.validate(transactionId)

    suspend fun validate(mdoc: MDoc, transactionId: TransactionId?) =
        mdoc.issuerSigned.issuerAuth?.tokenStatusListReference()?.validate(transactionId)

    private suspend fun StatusReference.validate(transactionId: TransactionId?) {
        catch({
            val currentStatus = with(getStatus()) { currentStatus().getOrThrow() }
            require(currentStatus == Status.Valid) { "Attestation status expected to be VALID but is $currentStatus" }
            transactionId?.let { logStatusCheckSuccess(it, this) }
        }) { error ->
            transactionId?.let { logStatusCheckFailed(it, this, error) }
            throw StatusCheckException("Attestation status check failed, ${error.message}", error)
        }
    }

    private fun getStatus(): GetStatus {
        val getStatusListToken: GetStatusListToken = GetStatusListToken.usingJwt(
            clock = clock.asKotlinClock(),
            httpClient = httpClient,
            verifyStatusListTokenSignature = { _, _ ->
                Result.success(Unit)
            },
        )
        return GetStatus(getStatusListToken)
    }

    private suspend fun logStatusCheckSuccess(transactionId: TransactionId, statusReference: StatusReference) {
        val event = PresentationEvent.AttestationStatusCheckSuccessful(transactionId, clock.now(), statusReference)
        publishPresentationEvent(event)
    }

    private suspend fun logStatusCheckFailed(transactionId: TransactionId, statusReference: StatusReference, error: Throwable) {
        val event = PresentationEvent.AttestationStatusCheckFailed(transactionId, clock.now(), statusReference, error.message)
        publishPresentationEvent(event)
    }
}
