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

package org.eclipse.apoapsis.sbom.sources

import com.charleskorn.kaml.Yaml
import com.charleskorn.kaml.YamlException
import com.charleskorn.kaml.YamlList
import com.charleskorn.kaml.YamlMap
import com.charleskorn.kaml.YamlNode
import com.charleskorn.kaml.YamlNull
import com.charleskorn.kaml.YamlScalar

import java.io.File

/**
 * The parser of SBOM source files, YAML files that list the remote [SbomSource]s to analyze:
 *
 * ```yaml
 * sources:
 *   # The URL of a Dependency-Track project page; "version" optionally selects another version of the project.
 *   - url: https://sbom.eclipse.org/projects/<uuid>
 *     version: latest
 *     # Optional metadata of the project, which takes precedence over the metadata in the SBOM.
 *     project:
 *       description: The product
 *       homepage: https://example.org/product
 *       authors: Example Inc.
 *       licenses: [EPL-2.0]
 *   # The URL of a sbomify component or product page.
 *   - https://app.sbomify.com/component/<id>/
 *   # The URL of any SBOM document; "type" overrides the type detected from the URL.
 *   - url: https://example.org/releases/1.0/bom.cdx.json
 *     type: document
 * ```
 */
object SbomSourceFile {
    private val ENTRY_KEYS = setOf("url", "type", "version", "project")
    private val PROJECT_KEYS = setOf("description", "homepage", "authors", "licenses")

    /** Parse the given source [file]. Throw an [IllegalArgumentException] if it is invalid. */
    fun parse(file: File): List<SbomSourceEntry> =
        try {
            parse(file.readText())
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid SBOM source file '${file.name}': ${e.message}", e)
        }

    /** Parse the given source file [text]. Throw an [IllegalArgumentException] if it is invalid. */
    fun parse(text: String): List<SbomSourceEntry> {
        val root = try {
            Yaml.default.parseToYamlNode(text)
        } catch (e: YamlException) {
            throw IllegalArgumentException("Invalid YAML: ${e.message}", e)
        }

        val map = root as? YamlMap ?: throw IllegalArgumentException("Expected a map with the key 'sources'.")
        val unknownKeys = map.entries.keys.map { it.content }.filter { it != "sources" }
        require(unknownKeys.isEmpty()) { "Unknown keys ${unknownKeys.joinToString { "'$it'" }}; expected 'sources'." }

        val sources = when (val node = map.get<YamlNode>("sources")) {
            null, is YamlNull -> emptyList()
            is YamlList -> node.items
            else -> throw IllegalArgumentException("'sources' must be a list.")
        }

        return sources.mapIndexed { index, entry ->
            try {
                parseEntry(entry)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid source #${index + 1}: ${e.message}", e)
            }
        }
    }

    private fun parseEntry(entry: YamlNode): SbomSourceEntry =
        when (entry) {
            is YamlScalar -> SbomSourceEntry(SbomSource.parse(entry.content))

            is YamlMap -> {
                entry.requireKnownKeys(ENTRY_KEYS)

                val url = requireNotNull(entry.scalar("url")) { "The key 'url' is missing." }
                val source =
                    SbomSource.parse(url, entry.scalar("type")?.let(SbomSourceType::forId), entry.scalar("version"))

                SbomSourceEntry(source, parseProject(entry.get<YamlNode>("project")))
            }

            else -> throw IllegalArgumentException("Expected a URL or a map with the key 'url'.")
        }

    private fun parseProject(node: YamlNode?): SbomProjectMetadata =
        when (node) {
            null, is YamlNull -> SbomProjectMetadata.EMPTY

            is YamlMap -> {
                node.requireKnownKeys(PROJECT_KEYS, "'project'")

                SbomProjectMetadata(
                    description = node.scalar("description"),
                    homepageUrl = node.scalar("homepage"),
                    authors = node.strings("authors"),
                    declaredLicenses = node.strings("licenses")
                )
            }

            else -> throw IllegalArgumentException("The value of 'project' must be a map.")
        }

    private fun YamlMap.requireKnownKeys(knownKeys: Set<String>, location: String? = null) {
        val unknownKeys = entries.keys.map { it.content }.filterNot { it in knownKeys }
        require(unknownKeys.isEmpty()) {
            "Unknown keys ${unknownKeys.joinToString { "'$it'" }}${location?.let { " in $it" }.orEmpty()}; " +
                "supported keys are ${knownKeys.joinToString { "'$it'" }}."
        }
    }

    private fun YamlMap.scalar(key: String): String? =
        when (val node = get<YamlNode>(key)) {
            null, is YamlNull -> null
            is YamlScalar -> node.content.trim().takeUnless { it.isEmpty() }
            else -> throw IllegalArgumentException("The value of '$key' must be a string.")
        }

    private fun YamlMap.strings(key: String): Set<String> {
        val values = when (val node = get<YamlNode>(key)) {
            null, is YamlNull -> emptyList()
            is YamlScalar -> listOf(node.content)

            is YamlList -> node.items.map { item ->
                (item as? YamlScalar)?.content
                    ?: throw IllegalArgumentException("The items of '$key' must be strings.")
            }

            else -> throw IllegalArgumentException("The value of '$key' must be a string or a list of strings.")
        }

        return values.mapNotNullTo(linkedSetOf()) { it.trim().takeUnless(String::isEmpty) }
    }
}
