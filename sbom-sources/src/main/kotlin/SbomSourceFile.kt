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
 *   # The URL of a sbomify component or product page.
 *   - https://app.sbomify.com/component/<id>/
 *   # The URL of any SBOM document; "type" overrides the type detected from the URL.
 *   - url: https://example.org/releases/1.0/bom.cdx.json
 *     type: document
 * ```
 */
object SbomSourceFile {
    private val ENTRY_KEYS = setOf("url", "type", "version")

    /** Parse the given source [file]. Throw an [IllegalArgumentException] if it is invalid. */
    fun parse(file: File): List<SbomSource> =
        try {
            parse(file.readText())
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid SBOM source file '${file.name}': ${e.message}", e)
        }

    /** Parse the given source file [text]. Throw an [IllegalArgumentException] if it is invalid. */
    fun parse(text: String): List<SbomSource> {
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

    private fun parseEntry(entry: YamlNode): SbomSource =
        when (entry) {
            is YamlScalar -> SbomSource.parse(entry.content)

            is YamlMap -> {
                val unknownKeys = entry.entries.keys.map { it.content }.filterNot { it in ENTRY_KEYS }
                require(unknownKeys.isEmpty()) {
                    "Unknown keys ${unknownKeys.joinToString { "'$it'" }}; supported keys are " +
                        "${ENTRY_KEYS.joinToString { "'$it'" }}."
                }

                val url = requireNotNull(entry.scalar("url")) { "The key 'url' is missing." }
                SbomSource.parse(url, entry.scalar("type")?.let(SbomSourceType::forId), entry.scalar("version"))
            }

            else -> throw IllegalArgumentException("Expected a URL or a map with the key 'url'.")
        }

    private fun YamlMap.scalar(key: String): String? =
        when (val node = get<YamlNode>(key)) {
            null, is YamlNull -> null
            is YamlScalar -> node.content
            else -> throw IllegalArgumentException("The value of '$key' must be a string.")
        }
}
