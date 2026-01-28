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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer

import org.springframework.scheduling.config.ScheduledTaskRegistrar
import kotlin.time.Duration
import kotlin.time.toJavaDuration

/**
 * Provides Kotlin syntactic sugar over [ScheduledTaskRegistrar.addFixedRateTask].
 */
internal fun ScheduledTaskRegistrar.addFixedRateTask(interval: Duration, task: Runnable) {
    addFixedRateTask(task, interval.toJavaDuration())
}
