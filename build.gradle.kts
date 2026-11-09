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

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    alias(libs.plugins.kotlinJvm) apply false
    alias(libs.plugins.ksp) apply false
}

val javaTargetVersion = providers.gradleProperty("javaTargetVersion").get()

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "maven-publish")

    extensions.configure<JavaPluginExtension> {
        withSourcesJar()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.release = javaTargetVersion.toInt()
    }

    extensions.configure<KotlinJvmProjectExtension> {
        compilerOptions {
            jvmTarget = JvmTarget.fromTarget(javaTargetVersion)
            freeCompilerArgs.add("-Xjdk-release=$javaTargetVersion")
            allWarningsAsErrors = true
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()

        // Pass the location of an optional SBOM corpus to the tests that analyze all its SBOMs.
        System.getenv("SBOM_CORPUS_DIR")?.let { environment("SBOM_CORPUS_DIR", it) }

        testLogging {
            events("passed", "skipped", "failed")
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
    }

    extensions.configure<PublishingExtension> {
        publications {
            create<MavenPublication>("maven") {
                from(components["java"])

                pom {
                    name = project.name
                    description = "Ingestion of CycloneDX and SPDX SBOMs into the OSS Review Toolkit (ORT)."
                    url = "https://heurtematte.github.io/ort-sbom-plugin/"

                    licenses {
                        license {
                            name = "EPL-2.0"
                            url = "https://www.eclipse.org/legal/epl-2.0/"
                        }
                    }

                    scm {
                        connection = "scm:git:https://github.com/heurtematte/ort-sbom-plugin.git"
                        url = "https://github.com/heurtematte/ort-sbom-plugin"
                    }
                }
            }
        }

        // Until the artifacts are on Maven Central. The credentials are read from the Gradle properties
        // "gitHubPackagesUsername" and "gitHubPackagesPassword", only when publishing to this repository.
        repositories {
            maven("https://maven.pkg.github.com/heurtematte/ort-sbom-plugin") {
                name = "gitHubPackages"
                credentials(PasswordCredentials::class)
            }
        }
    }
}

/** The modules whose jars are added to ORT Server; their other dependencies are already part of ORT Server. */
val ortServerPluginModules = listOf(":sbom-parser", ":sbom-sources", ":sbom-package-manager")

val ortServerPluginDir = layout.buildDirectory.dir("ort-server-plugin")

val ortServerPluginJars by tasks.registering(Sync::class) {
    group = "distribution"
    description = "Collects the jars of the plugin to add to the ORT Server images."

    from(ortServerPluginModules.map { project(it).tasks.named("jar") })
    into(ortServerPluginDir.map { it.dir("plugins") })
}

val ortServerPlugin by tasks.registering {
    group = "distribution"
    description = "Prepares the context to build ORT Server images with the plugin, see 'ort-server/Dockerfile'."

    dependsOn(ortServerPluginJars, ":sbom-package-manager:ortServerLibraries")
}
