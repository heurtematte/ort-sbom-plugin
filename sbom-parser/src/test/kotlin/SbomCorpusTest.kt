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

package org.eclipse.apoapsis.sbom.parser

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.should

import java.io.File

/** The environment variable pointing to a directory with SBOMs, for instance the output of `eclipse_sbom.py`. */
private const val CORPUS_ENV = "SBOM_CORPUS_DIR"

/** Files in the corpus directory that describe the corpus itself. */
private val CORPUS_FILES = setOf("index.json", "summary.json", "summary.md", "project.json")

/** Markers of documents in SBOM formats that are deliberately not supported. */
private val UNSUPPORTED_MARKERS = listOf("spdx.org/rdf/terms")

/** Markers of documents that are SBOMs, so that they must be detected. */
private val SBOM_MARKERS = listOf("bomFormat", "cyclonedx.org/schema/bom", "spdxVersion", "SPDXVersion", "spdx.org/rdf/3")

/**
 * A test that parses all SBOMs found below the directory referenced by the [CORPUS_ENV] environment variable. It is
 * skipped if the variable is not set. Files that are not SBOMs are skipped, and SBOMs in deliberately unsupported
 * formats are counted separately. The test fails if an SBOM is not detected or cannot be parsed, and prints the
 * number of parsed documents per format and specification version.
 */
class SbomCorpusTest : StringSpec({
    val corpus = System.getenv(CORPUS_ENV)?.let(::File)?.takeIf { it.isDirectory }

    "All SBOMs of the corpus should be parsed".config(enabled = corpus != null) {
        val files = corpus!!.walkTopDown().filter { it.isFile && it.name !in CORPUS_FILES }.sorted().toList()
        val failures = mutableListOf<String>()
        val unsupported = mutableListOf<String>()
        val parsedByKind = sortedMapOf<String, Int>()
        var skipped = 0

        files.forEach { file ->
            val relativePath = file.relativeTo(corpus).invariantSeparatorsPath
            val content = file.readBytes()
            val text = content.toUtf8().decodeToString()

            when {
                SbomParser.detectFormat(content) == null && UNSUPPORTED_MARKERS.any { it in text } ->
                    unsupported += relativePath

                SbomParser.detectFormat(content) == null && SBOM_MARKERS.none { it in text } -> skipped++

                else -> runCatching { SbomParser.parse(content) }.onSuccess { document ->
                    val kind = "${document.format.displayName} ${document.specVersion}"
                    parsedByKind[kind] = (parsedByKind[kind] ?: 0) + 1
                    println(
                        "OK   $relativePath: $kind, ${document.components.size} components, " +
                            "${document.relationships.values.sumOf { it.size }} relationships, " +
                            "${document.roots.size} root(s), ${document.warnings.size} warning(s)"
                    )
                }.onFailure {
                    println("FAIL $relativePath: ${it.message}")
                    failures += "$relativePath: ${it.message}"
                }
            }
        }

        println("Parsed documents by format and specification version:")
        parsedByKind.forEach { (kind, count) -> println("  %5d  %s".format(count, kind)) }
        println(
            "Parsed ${parsedByKind.values.sum()} SBOMs, ${failures.size} failure(s), ${unsupported.size} in " +
                "unsupported formats, $skipped files that are not SBOMs."
        )
        unsupported.forEach { println("UNSUPPORTED $it") }

        failures should beEmpty()
    }
})
