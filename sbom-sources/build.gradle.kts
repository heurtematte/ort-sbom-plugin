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

description = "Retrieval of SBOMs from Dependency-Track, sbomify, or any URL."

dependencies {
    api(project(":sbom-parser"))

    implementation(libs.kaml)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.slf4j)

    testImplementation(testFixtures(project(":sbom-parser")))

    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.kotest.runner.junit5)
}
