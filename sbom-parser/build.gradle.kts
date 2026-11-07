/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */

plugins {
    `java-test-fixtures`
}

description = "Parsers for CycloneDX and SPDX SBOMs into a format-independent model."

dependencies {
    implementation(libs.cyclonedx.core.java)
    implementation(libs.kaml)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.kotest.runner.junit5)
}
