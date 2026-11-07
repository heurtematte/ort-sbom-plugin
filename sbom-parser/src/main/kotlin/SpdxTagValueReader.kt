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

import com.charleskorn.kaml.Yaml
import com.charleskorn.kaml.YamlConfiguration
import com.charleskorn.kaml.YamlException
import com.charleskorn.kaml.YamlList
import com.charleskorn.kaml.YamlMap
import com.charleskorn.kaml.YamlNode
import com.charleskorn.kaml.YamlNull
import com.charleskorn.kaml.YamlScalar
import com.charleskorn.kaml.YamlTaggedNode

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * A reader for SPDX 2.x documents in the tag-value format. It converts the document to the tree structure of the JSON
 * format, so that it can be processed by [Spdx2Parser]. Only the document, package, and relationship information is
 * retained; files, snippets, and extracted licensing information are skipped.
 */
internal object SpdxTagValueReader {
    /** The mapping from package tags to the properties of packages in the JSON format. */
    private val PACKAGE_TAGS = mapOf(
        "SPDXID" to "SPDXID",
        "PackageVersion" to "versionInfo",
        "PackageFileName" to "packageFileName",
        "PackageSupplier" to "supplier",
        "PackageOriginator" to "originator",
        "PackageDownloadLocation" to "downloadLocation",
        "FilesAnalyzed" to "filesAnalyzed",
        "PackageHomePage" to "homepage",
        "PackageLicenseConcluded" to "licenseConcluded",
        "PackageLicenseDeclared" to "licenseDeclared",
        "PackageCopyrightText" to "copyrightText",
        "PackageSummary" to "summary",
        "PackageDescription" to "description",
        "PrimaryPackagePurpose" to "primaryPackagePurpose"
    )

    /** The mapping from document tags to the properties of the document in the JSON format. */
    private val DOCUMENT_TAGS = mapOf(
        "SPDXVersion" to "spdxVersion",
        "DataLicense" to "dataLicense",
        "SPDXID" to "SPDXID",
        "DocumentName" to "name",
        "DocumentNamespace" to "documentNamespace"
    )

    /** Tags that start an element whose properties are skipped. */
    private val SKIPPED_ELEMENT_TAGS = setOf("FileName", "SnippetSPDXID", "LicenseID")

    private enum class Section { DOCUMENT, PACKAGE, SKIPPED }

    fun read(text: String): JsonObject {
        val document = mutableMapOf<String, JsonElement>()
        val creators = mutableListOf<JsonElement>()
        val creationInfo = mutableMapOf<String, JsonElement>()
        val packages = mutableListOf<MutableMap<String, JsonElement>>()
        val relationships = mutableListOf<JsonElement>()

        var section = Section.DOCUMENT

        tagValuePairs(text).forEach { (tag, value) ->
            when (tag) {
                "PackageName" -> {
                    section = Section.PACKAGE
                    packages += mutableMapOf<String, JsonElement>("name" to JsonPrimitive(value))
                }

                in SKIPPED_ELEMENT_TAGS -> section = Section.SKIPPED

                "Relationship" -> value.split(WHITESPACE).takeIf { it.size >= 3 }?.let { (source, type, target) ->
                    relationships += JsonObject(
                        mapOf(
                            "spdxElementId" to JsonPrimitive(source),
                            "relationshipType" to JsonPrimitive(type),
                            "relatedSpdxElement" to JsonPrimitive(target)
                        )
                    )
                }

                "Creator" -> creators += JsonPrimitive(value)

                "Created" -> creationInfo["created"] = JsonPrimitive(value)

                else -> when (section) {
                    Section.DOCUMENT -> DOCUMENT_TAGS[tag]?.let { document[it] = JsonPrimitive(value) }
                    Section.PACKAGE -> packages.last().addPackageProperty(tag, value)
                    Section.SKIPPED -> Unit
                }
            }
        }

        creationInfo["creators"] = JsonArray(creators)
        document["creationInfo"] = JsonObject(creationInfo)
        document["packages"] = JsonArray(packages.map(::JsonObject))
        document["relationships"] = JsonArray(relationships)

        return JsonObject(document)
    }

    private fun MutableMap<String, JsonElement>.addPackageProperty(tag: String, value: String) {
        when (tag) {
            "PackageChecksum" -> {
                val checksum = JsonObject(
                    mapOf(
                        "algorithm" to JsonPrimitive(value.substringBefore(':').trim()),
                        "checksumValue" to JsonPrimitive(value.substringAfter(':').trim())
                    )
                )
                this["checksums"] = JsonArray((this["checksums"] as? JsonArray).orEmpty() + checksum)
            }

            "ExternalRef" -> value.split(WHITESPACE, limit = 3).takeIf { it.size == 3 }?.let { parts ->
                val (category, type, locator) = parts
                val externalRef = JsonObject(
                    mapOf(
                        "referenceCategory" to JsonPrimitive(category),
                        "referenceType" to JsonPrimitive(type),
                        "referenceLocator" to JsonPrimitive(locator)
                    )
                )
                this["externalRefs"] = JsonArray((this["externalRefs"] as? JsonArray).orEmpty() + externalRef)
            }

            else -> PACKAGE_TAGS[tag]?.let { this[it] = JsonPrimitive(value) }
        }
    }

    /**
     * Split the [text] into tag-value pairs. Values enclosed in `<text>` and `</text>` may span multiple lines, and
     * lines starting with `#` are comments.
     */
    internal fun tagValuePairs(text: String): List<Pair<String, String>> {
        val pairs = mutableListOf<Pair<String, String>>()
        val lines = text.lines()
        var index = 0

        while (index < lines.size) {
            val line = lines[index++]
            if (line.isBlank() || line.trimStart().startsWith("#")) continue

            val colon = line.indexOf(':')
            if (colon <= 0) continue

            val tag = line.substring(0, colon).trim()
            var value = line.substring(colon + 1).trim()

            if (value.startsWith("<text>")) {
                val content = StringBuilder(value.removePrefix("<text>"))
                while ("</text>" !in content && index < lines.size) content.append('\n').append(lines[index++])
                value = content.toString().substringBefore("</text>").trim()
            }

            pairs += tag to value
        }

        return pairs
    }

    private val WHITESPACE = Regex("\\s+")
}

/**
 * Convert the YAML [text] to a JSON tree. All scalar values are converted to strings.
 */
internal fun yamlToJson(text: String): JsonElement =
    try {
        Yaml(configuration = YamlConfiguration(codePointLimit = Int.MAX_VALUE)).parseToYamlNode(text).toJsonElement()
    } catch (e: YamlException) {
        throw SbomParseException("Invalid YAML document: ${e.message}", e)
    }

private fun YamlNode.toJsonElement(): JsonElement =
    when (this) {
        is YamlMap -> JsonObject(entries.entries.associate { (key, value) -> key.content to value.toJsonElement() })
        is YamlList -> JsonArray(items.map { it.toJsonElement() })
        is YamlScalar -> JsonPrimitive(content)
        is YamlNull -> JsonNull
        is YamlTaggedNode -> innerNode.toJsonElement()
    }

private fun JsonArray?.orEmpty(): List<JsonElement> = this ?: emptyList()
