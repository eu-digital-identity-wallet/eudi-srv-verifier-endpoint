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
package eu.europa.ec.eudi.verifier.endpoint.domain

/**
 * [JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)
 */
object RFC9101 {
    const val REQUEST: String = "request"
    const val REQUEST_URI: String = "request_uri"

    const val REQUEST_OBJECT_MEDIA_TYPE: String = "application/oauth-authz-req+jwt"
    const val REQUEST_OBJECT_MEDIA_SUBTYPE: String = "oauth-authz-req+jwt"

    const val REQUEST_OBJECT_SIGNING_ALGORITHMS_SUPPORTED: String = "request_object_signing_alg_values_supported"
    const val REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED = "request_object_encryption_alg_values_supported"
    const val REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED = "request_object_encryption_enc_values_supported"
}
