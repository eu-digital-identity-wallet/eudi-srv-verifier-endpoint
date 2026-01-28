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
package eu.europa.ec.eudi.verifier.endpoint.domain

/**
 * [OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html)
 */
object RFC6749 {

    const val CLIENT_ID: String = "client_id"
    const val STATE: String = "state"
    const val ERROR: String = "error"
    const val ERROR_DESCRIPTION: String = "error_description"

    const val RESPONSE_MODE: String = "response_mode"
}
