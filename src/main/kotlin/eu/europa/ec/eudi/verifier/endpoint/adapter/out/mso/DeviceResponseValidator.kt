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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import arrow.core.NonEmptyList
import arrow.core.mapOrAccumulate
import arrow.core.raise.Raise
import arrow.core.raise.context.bind
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import arrow.core.raise.context.withError
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.dataretrieval.DeviceResponseStatus
import id.walt.mdoc.doc.MDoc

/**
 * An invalid document inside a device response
 */
data class InvalidDocument(
    val index: Int,
    val documentType: String,
    val errors: NonEmptyList<DocumentError>,
)

/**
 * Errors related to device response
 */
sealed interface DeviceResponseError {
    /**
     * Given vp_token cannot be decoded to a device response
     */
    data object CannotBeDecoded : DeviceResponseError

    /**
     * Device response didn't have an OK status
     */
    data class NotOkDeviceResponseStatus(
        val status: Number,
    ) : DeviceResponseError

    /**
     * Invalid documents found within device response
     */
    data class InvalidDocuments(
        val invalidDocuments: NonEmptyList<InvalidDocument>,
    ) : DeviceResponseError
}

class DeviceResponseValidator(
    private val documentValidator: DocumentValidator,
) {
    /**
     * Validates the given verifier presentation
     * It could a vp_token or an element of an array vp_token
     */
    context(_: Raise<DeviceResponseError>)
    suspend fun ensureValid(
        vp: String,
        transactionId: TransactionId? = null,
        handoverInfo: HandoverInfo? = null,
    ): List<MDoc> {
        val deviceResponse = ensureCanBeDecoded(vp)
        return ensureValid(deviceResponse, transactionId, handoverInfo)
    }

    context(_: Raise<DeviceResponseError>)
    suspend fun ensureValid(
        deviceResponse: DeviceResponse,
        transactionId: TransactionId?,
        handoverInfo: HandoverInfo?,
    ): List<MDoc> {
        ensureStatusIsOk(deviceResponse)
        return ensureValidDocuments(deviceResponse, documentValidator, transactionId, handoverInfo)
    }
}

context(_: Raise<DeviceResponseError.CannotBeDecoded>)
private fun ensureCanBeDecoded(vp: String): DeviceResponse =
    try {
        DeviceResponse.decodeFromCborBase64Url(vp)
    } catch (_: Throwable) {
        raise(DeviceResponseError.CannotBeDecoded)
    }

context(_: Raise<DeviceResponseError.NotOkDeviceResponseStatus>)
private fun ensureStatusIsOk(deviceResponse: DeviceResponse) {
    val status = deviceResponse.status
    ensure(DeviceResponseStatus.OK.status.toInt() == status.value.toInt()) {
        DeviceResponseError.NotOkDeviceResponseStatus(status.value)
    }
}

context(_: Raise<DeviceResponseError.InvalidDocuments>)
private suspend fun ensureValidDocuments(
    deviceResponse: DeviceResponse,
    documentValidator: DocumentValidator,
    transactionId: TransactionId?,
    handoverInfo: HandoverInfo?,
): List<MDoc> =
    deviceResponse.documents
        .withIndex()
        .mapOrAccumulate { (index, document) ->
            withError({ documentErrors -> InvalidDocument(index, document.docType.value, documentErrors) }) {
                documentValidator
                    .ensureValid(document, transactionId, handoverInfo)
            }
        }.mapLeft(DeviceResponseError::InvalidDocuments)
        .bind()
