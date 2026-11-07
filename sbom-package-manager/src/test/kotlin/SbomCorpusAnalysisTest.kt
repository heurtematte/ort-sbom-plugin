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

package org.eclipse.apoapsis.sbom.packagemanager

import io.kotest.core.spec.style.StringSpec
import io.kotest.engine.spec.tempdir
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.should

import java.io.File

import org.eclipse.apoapsis.sbom.parser.SbomParser

import org.ossreviewtoolkit.analyzer.Analyzer
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration

/** The environment variable pointing to a directory with SBOMs, for instance the output of `eclipse_sbom.py`. */
private const val CORPUS_ENV = "SBOM_CORPUS_DIR"

/**
 * A test that runs the ORT Analyzer with the SBOM package manager on every SBOM found below the directory referenced
 * by the [CORPUS_ENV] environment variable. It is skipped if the variable is not set. It checks that every SBOM results
 * in projects and packages without errors.
 */
class SbomCorpusAnalysisTest : StringSpec({
    val corpus = System.getenv(CORPUS_ENV)?.let(::File)?.takeIf { it.isDirectory }

    "All SBOMs of the corpus should be analyzed".config(enabled = corpus != null) {
        val files = corpus!!.walkTopDown()
            .filter { it.isFile && SbomParser.detectFormat(it.readBytes()) != null }
            .sorted()
            .toList()
        val failures = mutableListOf<String>()

        files.forEach { file ->
            val relativePath = file.relativeTo(corpus).invariantSeparatorsPath
            val format = checkNotNull(SbomParser.detectFormat(file.readBytes()))
            val dir = tempdir()
            file.copyTo(dir.resolve("sbom.${format.fileExtension}"))

            runCatching {
                val analyzer = Analyzer(AnalyzerConfiguration(enabledPackageManagers = listOf("SBOM")))
                analyzer.analyze(analyzer.findManagedFiles(dir, listOf(SbomFactory())))
            }.onSuccess { result ->
                val errors = result.getAnalyzerIssues(minSeverity = Severity.ERROR).values.flatten()
                val projects = result.getProjects()
                println(
                    "${if (errors.isEmpty()) "OK  " else "FAIL"} $relativePath: ${projects.size} project(s) " +
                        "${projects.map { it.id.toCoordinates() }}, ${result.getPackages().size} packages, " +
                        "${result.getAnalyzerIssues().values.sumOf { it.size }} issue(s)"
                )
                if (errors.isNotEmpty()) {
                    println("     -> ${errors.joinToString { it.message.take(300) }}")
                    failures += "$relativePath: ${errors.joinToString { it.message }}"
                }
            }.onFailure {
                println("FAIL $relativePath: $it")
                failures += "$relativePath: $it"
            }
        }

        println("Analyzed ${files.size - failures.size} of ${files.size} SBOMs.")
        failures should beEmpty()
    }
})
