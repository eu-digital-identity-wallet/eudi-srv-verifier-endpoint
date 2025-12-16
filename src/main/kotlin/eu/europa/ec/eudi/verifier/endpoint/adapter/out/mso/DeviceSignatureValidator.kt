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

import COSE.AlgorithmID
import COSE.OneKey
import arrow.core.Either
import arrow.core.raise.catch
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.right
import com.upokecenter.cbor.CBORObject
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mdocauth.DeviceAuthentication

sealed interface DeviceSignatureValidationFailure {
    data object MissingDeviceSignature : DeviceSignatureValidationFailure
    class DeviceKeyCannotBeParsed(val cause: Throwable) : DeviceSignatureValidationFailure
    class DeviceSignatureValidationFailed(val cause: Throwable) : DeviceSignatureValidationFailure
}

fun interface DeviceSignatureValidator {

    fun MDoc.validateDeviceSignature(
        deviceAuthentication: DeviceAuthentication,
    ): Either<DeviceSignatureValidationFailure, DeviceAuthentication>

    companion object {
        val Default: DeviceSignatureValidator = DeviceSignatureValidator { deviceAuthentication ->
            either {
                val deviceSignature = ensureNotNull(deviceSigned?.deviceAuth?.deviceSignature) {
                    DeviceSignatureValidationFailure.MissingDeviceSignature
                }

                val keyId = "DEVICE_KEY"
                val cryptoProvider = catch({
                    val algorithmId = AlgorithmID.FromCBOR(CBORObject.FromObject(deviceSignature.algorithm))
                    val deviceKeyInfo = checkNotNull(MSO).deviceKeyInfo
                    val oneKey = OneKey(CBORObject.DecodeFromBytes(deviceKeyInfo.deviceKey.toCBOR()))
                    val publicKey = oneKey.AsPublicKey()

                    SimpleCOSECryptoProvider(
                        listOf(
                            COSECryptoProviderKeyInfo(keyID = keyId, algorithmID = algorithmId, publicKey = publicKey),
                        ),
                    )
                }) { error -> raise(DeviceSignatureValidationFailure.DeviceKeyCannotBeParsed(error)) }

                catch({
                    verifyDeviceSignature(deviceAuthentication, cryptoProvider, keyId)
                }) { error -> raise(DeviceSignatureValidationFailure.DeviceSignatureValidationFailed(error)) }

                deviceAuthentication
            }
        }

        val NoOp: DeviceSignatureValidator = DeviceSignatureValidator { it.right() }
    }
}
