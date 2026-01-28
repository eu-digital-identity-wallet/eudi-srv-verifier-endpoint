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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.statium.StatusIndex
import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.statium.TokenStatusListSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import kotlinx.serialization.json.JsonObject

fun SdJwt<SignedJWT>.statusReference(): StatusReference? = jwt.statusReference()
fun SdJwtAndKbJwt<SignedJWT>.statusReference(): StatusReference? = sdJwt.statusReference()

fun SdJwt<SignedJWT>.status(): JsonObject? = jwt.jwtClaimsSet.getJSONObjectClaim(TokenStatusListSpec.STATUS)?.toJsonObject()
fun SdJwtAndKbJwt<SignedJWT>.status(): JsonObject? = sdJwt.status()

private fun SignedJWT.statusReference(): StatusReference? {
    val statusElement = jwtClaimsSet.getJSONObjectClaim(TokenStatusListSpec.STATUS) ?: return null
    val statusJsonObject = statusElement.toJsonObject()
    val statusListElement = statusJsonObject[TokenStatusListSpec.STATUS_LIST]
    requireNotNull(statusListElement) {
        "Expected status_list element but not found"
    }
    require(statusListElement is JsonObject) {
        "Malformed status_list element"
    }

    val index = StatusIndex(statusListElement[TokenStatusListSpec.IDX]?.decodeAs<Int>()?.getOrThrow()!!)
    val uri = statusListElement[TokenStatusListSpec.URI]?.decodeAs<String>()!!.getOrThrow()

    return StatusReference(index, uri)
}
