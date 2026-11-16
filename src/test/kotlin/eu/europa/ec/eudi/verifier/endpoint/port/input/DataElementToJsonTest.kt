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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import id.walt.mdoc.dataelement.DateTimeElement
import id.walt.mdoc.dataelement.FullDateElement
import id.walt.mdoc.dataelement.ListElement
import kotlinx.datetime.LocalDate
import kotlinx.datetime.toDeprecatedInstant
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Instant

internal class DataElementToJsonTest {
    @Test
    fun `a full-date is converted to its ISO 8601 calendar date`() {
        val birthDate = FullDateElement(LocalDate(1985, 3, 15))

        assertEquals(JsonPrimitive("1985-03-15"), birthDate.toJsonElement())
    }

    @Test
    fun `a date-time is converted to an ISO 8601 instant in UTC`() {
        val issuedAt = DateTimeElement(Instant.parse("2026-11-12T19:42:00Z").toDeprecatedInstant())

        assertEquals(JsonPrimitive("2026-11-12T19:42:00Z"), issuedAt.toJsonElement())
    }

    @Test
    fun `dates nested in a list are converted too`() {
        val dates = ListElement(listOf(FullDateElement(LocalDate(2026, 1, 1)), FullDateElement(LocalDate(2026, 12, 31))))

        assertEquals(JsonArray(listOf(JsonPrimitive("2026-01-01"), JsonPrimitive("2026-12-31"))), dates.toJsonElement())
    }
}
