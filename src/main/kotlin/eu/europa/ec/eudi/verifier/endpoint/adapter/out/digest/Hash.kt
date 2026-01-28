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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.digest

import eu.europa.ec.eudi.verifier.endpoint.domain.HashAlgorithm
import java.security.MessageDigest

internal fun hash(data: ByteArray, algorithm: HashAlgorithm): ByteArray {
    val messageDigest = when (algorithm) {
        HashAlgorithm.SHA_256 -> MessageDigest.getInstance("SHA-256")
        HashAlgorithm.SHA_384 -> MessageDigest.getInstance("SHA-384")
        HashAlgorithm.SHA_512 -> MessageDigest.getInstance("SHA-512")
        HashAlgorithm.SHA3_224 -> MessageDigest.getInstance("SHA3-224")
        HashAlgorithm.SHA3_256 -> MessageDigest.getInstance("SHA3-256")
        HashAlgorithm.SHA3_384 -> MessageDigest.getInstance("SHA3-384")
        HashAlgorithm.SHA3_512 -> MessageDigest.getInstance("SHA3-512")
    }

    messageDigest.update(data)
    return messageDigest.digest()
}

internal fun hash(data: String, algorithm: HashAlgorithm): ByteArray = hash(data.toByteArray(), algorithm)
