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
    implementation(project(":sbom-sources"))

    implementation(libs.slf4j)
    implementation(ortLibs.downloader)
    implementation(ortLibs.utils.common)
    implementation(ortLibs.utils.ort)
    implementation(ortLibs.utils.spdxExpression)

    ksp(ortLibs.analyzer)
    ksp(ortLibs.ortPlugins.compiler)

    testImplementation(testFixtures(project(":sbom-parser")))
    testImplementation(testFixtures(project(":sbom-sources")))

    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.kotest.runner.junit5)
}

/**
 * Write the file names of the libraries the plugin was compiled against, which the ORT Server images must contain, for
 * the check in 'ort-server/Dockerfile': all ORT libraries must match exactly, and the other libraries the plugin modules
 * use directly should.
 */
val ortServerLibraries by tasks.registering {
    group = "distribution"
    description = "Lists the libraries the plugin expects in the ORT Server images."

    val runtimeClasspath = configurations.runtimeClasspath

    // The modules the plugin modules depend on directly.
    val directModules = runtimeClasspath.flatMap { configuration ->
        configuration.incoming.resolutionResult.rootComponent.map { root ->
            val modules = sortedSetOf<String>()
            val queue = ArrayDeque(listOf(root))
            val visited = mutableSetOf<ComponentIdentifier>()

            while (queue.isNotEmpty()) {
                val component = queue.removeFirst()
                if (!visited.add(component.id)) continue

                component.dependencies.filterIsInstance<ResolvedDependencyResult>().forEach { dependency ->
                    when (val id = dependency.selected.id) {
                        is ProjectComponentIdentifier -> queue += dependency.selected
                        is ModuleComponentIdentifier -> modules += "${id.group}:${id.module}"
                    }
                }
            }

            modules.toList()
        }
    }

    val libraries = runtimeClasspath.flatMap { configuration ->
        configuration.incoming.artifacts.resolvedArtifacts.map { artifacts ->
            artifacts.mapNotNull { artifact ->
                (artifact.id.componentIdentifier as? ModuleComponentIdentifier)?.let {
                    "${it.group}:${it.module} ${artifact.file.name}"
                }
            }
        }
    }

    val outputDir = rootProject.layout.buildDirectory.dir("ort-server-plugin")
    inputs.property("directModules", directModules)
    inputs.property("libraries", libraries)
    outputs.files(outputDir.map { listOf(it.file("required-libs.txt"), it.file("expected-libs.txt")) })

    doLast {
        val entries = libraries.get().map { it.substringBefore(' ') to it.substringAfter(' ') }
        val (ortLibraries, otherLibraries) = entries.partition { (module, _) -> module.startsWith("org.ossreviewtoolkit") }
        val direct = directModules.get().toSet()

        fun List<Pair<String, String>>.write(fileName: String) =
            outputDir.get().file(fileName).asFile.writeText(map { it.second }.sorted().joinToString("\n", postfix = "\n"))

        ortLibraries.write("required-libs.txt")
        // Kotlin Multiplatform libraries resolve to the artifacts of their "-jvm" variant.
        otherLibraries.filter { (module, _) -> module.removeSuffix("-jvm") in direct }.write("expected-libs.txt")
    }
}
