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

rootProject.name = "ort-sbom-plugin"

include(":sbom-parser")
include(":sbom-sources")
include(":sbom-package-manager")

dependencyResolutionManagement {
    repositories {
        mavenCentral()

        // The ORT Analyzer depends on the Gradle Tooling API, which is only published here.
        exclusiveContent {
            forRepository {
                maven("https://repo.gradle.org/gradle/libs-releases/")
            }

            filter {
                includeGroup("org.gradle")
            }
        }
    }

    versionCatalogs {
        create("ortLibs") {
            from("org.ossreviewtoolkit:version-catalog:99.0.0")
        }
    }
}
