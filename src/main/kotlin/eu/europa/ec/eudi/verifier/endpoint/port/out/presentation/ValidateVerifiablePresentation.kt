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
package eu.europa.ec.eudi.verifier.endpoint.port.out.presentation

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.raise.either
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError

/**
 * Validates Verifiable Presentations.
 *
 * For MsoMdoc, validates the Verifiable Presentation contains a DeviceResponse signed by a trusted issuer.
 * For SD-JWT VC, validates the Verifiable Presentation contains an SD-JWT+KB, with a KeyBinding JWT that contains
 * the expected Audience and Nonce.
 * For all other formats, no validations are performed.
 */
fun interface ValidateVerifiablePresentation {

    suspend operator fun invoke(
        presentation: Presentation.RequestObjectRetrieved,
        verifiablePresentation: VerifiablePresentation,
        transactionData: NonEmptyList<TransactionData>?,
    ): Either<WalletResponseValidationError, VerifiablePresentation>

    companion object {
        val NoOp: ValidateVerifiablePresentation =
            ValidateVerifiablePresentation { _, verifiablePresentation, _ -> either { verifiablePresentation } }
    }
}
