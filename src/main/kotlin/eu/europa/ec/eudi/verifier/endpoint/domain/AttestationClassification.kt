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

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable

@Serializable
data class AttestationClassifications(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val pid: AttestationIdentifiers = AttestationIdentifiers(),
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val qeaa: AttestationIdentifiers = AttestationIdentifiers(),
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val pubeaa: AttestationIdentifiers = AttestationIdentifiers(),
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val eaa: List<EAAAttestationClassification> = emptyList(),
)

@Serializable
data class AttestationIdentifiers(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val vcts: List<String> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val docTypes: List<String> = emptyList(),
)

@Serializable
data class EAAAttestationClassification(
    @Required
    val useCase: String,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val vcts: List<String> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @Required
    val docTypes: List<String> = emptyList(),
)
