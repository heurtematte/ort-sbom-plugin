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
    alias(libs.plugins.ksp)
}

description = "An ORT package manager plugin that ingests existing CycloneDX and SPDX SBOMs."

dependencies {
    api(ortLibs.analyzer)
    api(ortLibs.model)

    implementation(project(":sbom-parser"))

    implementation(libs.slf4j)
    implementation(ortLibs.downloader)
    implementation(ortLibs.utils.ort)
    implementation(ortLibs.utils.spdxExpression)

    ksp(ortLibs.analyzer)
    ksp(ortLibs.ortPlugins.compiler)

    testImplementation(testFixtures(project(":sbom-parser")))

    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.kotest.runner.junit5)
}
