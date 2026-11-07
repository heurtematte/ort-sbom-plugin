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

import java.io.File

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * The entry point for parsing SBOMs. The format of a document is determined from its content, not from its file name,
 * and the document is converted to a format-independent [SbomDocument].
 *
 * Supported formats are CycloneDX (JSON and XML, all specification versions), SPDX 2.x (JSON, YAML, tag-value, and
 * XML), and SPDX 3.0 (JSON-LD). Documents may be encoded in UTF-8, UTF-16, or UTF-32. The specification version is
 * taken from the document; versions the parser has not been tested with are accepted with a warning.
 */
object SbomParser {
    private val CYCLONEDX_JSON_REGEX = """"bomFormat"\s*:\s*"CycloneDX"""".toRegex()
    private val CYCLONEDX_XML_REGEX = """xmlns(:\w+)?\s*=\s*["']http://cyclonedx\.org/schema/bom/""".toRegex()
    private val SPDX_JSON_REGEX = """"spdxVersion"\s*:""".toRegex()
    private val SPDX3_CONTEXT_REGEX = """spdx\.org/rdf/3\.""".toRegex()
    private val SPDX_TAG_VALUE_REGEX = """(?m)^\s*SPDXVersion\s*:\s*SPDX-""".toRegex()
    private val SPDX_YAML_REGEX = """(?m)^\s*["']?spdxVersion["']?\s*:""".toRegex()
    private val SPDX_RDF_REGEX = """spdx\.org/rdf/terms""".toRegex()
    private val SPDX_XML_REGEX = """<Document[\s>][\s\S]*<spdxVersion>""".toRegex()

    /** The specification versions the parsers have been tested with, by format family. */
    private val TESTED_CYCLONEDX_VERSIONS = (0..7).map { "1.$it" }.toSet()
    private val TESTED_SPDX2_VERSIONS = (0..3).map { "SPDX-2.$it" }.toSet()
    private val TESTED_SPDX3_VERSIONS = setOf("SPDX-3.0.0", "SPDX-3.0.1")

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Determine the [SbomFormat] of the given [content] by inspecting its beginning, or return *null* if it does not
     * look like a supported SBOM. As only the beginning of the document is inspected, a detected format does not
     * guarantee that the document can be parsed.
     */
    fun detectFormat(content: ByteArray): SbomFormat? {
        val head = content.toUtf8().head()
        val firstChar = head.firstOrNull { !it.isWhitespace() }

        return when {
            firstChar == '{' -> when {
                CYCLONEDX_JSON_REGEX.containsMatchIn(head) -> SbomFormat.CYCLONEDX_JSON
                SPDX3_CONTEXT_REGEX.containsMatchIn(head) -> SbomFormat.SPDX3_JSON_LD
                SPDX_JSON_REGEX.containsMatchIn(head) -> SbomFormat.SPDX_JSON
                else -> null
            }

            firstChar == '<' -> when {
                CYCLONEDX_XML_REGEX.containsMatchIn(head) -> SbomFormat.CYCLONEDX_XML
                SPDX_XML_REGEX.containsMatchIn(head) -> SbomFormat.SPDX_XML
                else -> null
            }

            SPDX_TAG_VALUE_REGEX.containsMatchIn(head) -> SbomFormat.SPDX_TAG_VALUE

            SPDX_YAML_REGEX.containsMatchIn(head) -> SbomFormat.SPDX_YAML

            else -> null
        }
    }

    /** Parse the SBOM in the given [file]. */
    fun parse(file: File): SbomDocument = parse(file.readBytes())

    /**
     * Parse the SBOM in the given [content]. Throw an [SbomParseException] if the format is not supported or the
     * document is invalid.
     */
    fun parse(content: ByteArray): SbomDocument {
        if (content.isEmpty()) throw SbomParseException("The document is empty.")

        val utf8Content = content.toUtf8()
        val format = detectFormat(utf8Content) ?: detectFormatFromStructure(utf8Content)

        return parse(utf8Content, format).withVersionWarning()
    }

    private fun parse(content: ByteArray, format: SbomFormat): SbomDocument =
        when (format) {
            SbomFormat.CYCLONEDX_JSON, SbomFormat.CYCLONEDX_XML -> CycloneDxParser.parse(content, format)

            SbomFormat.SPDX_JSON -> Spdx2Parser.parse(parseJsonObject(content), format)

            SbomFormat.SPDX_YAML -> Spdx2Parser.parse(
                yamlToJson(content.decodeToString()) as? JsonObject
                    ?: throw SbomParseException("The YAML document is not a mapping."),
                format
            )

            SbomFormat.SPDX_TAG_VALUE -> Spdx2Parser.parse(SpdxTagValueReader.read(content.decodeToString()), format)

            SbomFormat.SPDX_XML -> Spdx2Parser.parse(SpdxXmlReader.read(content), format)

            SbomFormat.SPDX3_JSON_LD -> Spdx3Parser.parse(parseJsonObject(content))
        }

    /** Add a warning to this document if its specification version has not been tested. */
    private fun SbomDocument.withVersionWarning(): SbomDocument {
        val testedVersions = when (format) {
            SbomFormat.CYCLONEDX_JSON, SbomFormat.CYCLONEDX_XML -> TESTED_CYCLONEDX_VERSIONS
            SbomFormat.SPDX3_JSON_LD -> TESTED_SPDX3_VERSIONS
            else -> TESTED_SPDX2_VERSIONS
        }

        return if (specVersion in testedVersions) {
            this
        } else {
            val warning = "The ${format.displayName} specification version '$specVersion' has not been tested; " +
                "the document is interpreted like the closest tested version."
            copy(warnings = warnings + warning)
        }
    }

    /**
     * Determine the format of a document whose beginning does not reveal it, for instance because the identifying
     * properties of a JSON document come late. Throw an [SbomParseException] if the format is not supported.
     */
    private fun detectFormatFromStructure(content: ByteArray): SbomFormat {
        val head = content.head()

        if (SPDX_RDF_REGEX.containsMatchIn(head)) {
            throw SbomParseException("SPDX documents in RDF/XML format are not supported. Convert them to SPDX JSON.")
        }

        if (head.firstOrNull { !it.isWhitespace() } == '{') {
            val root = parseJsonObject(content)
            return when {
                root.string("bomFormat") == "CycloneDX" -> SbomFormat.CYCLONEDX_JSON
                "spdxVersion" in root -> SbomFormat.SPDX_JSON
                root.isSpdx3() -> SbomFormat.SPDX3_JSON_LD
                else -> throw SbomParseException("The JSON document is neither a CycloneDX nor an SPDX document.")
            }
        }

        throw SbomParseException(
            "The document is not in a supported SBOM format. Supported formats are " +
                SbomFormat.entries.joinToString { it.displayName } + "."
        )
    }

    private fun parseJsonObject(content: ByteArray): JsonObject =
        try {
            json.parseToJsonElement(content.decodeToString()) as? JsonObject
                ?: throw SbomParseException("The JSON document is not an object.")
        } catch (e: SerializationException) {
            throw SbomParseException("Invalid JSON document: ${e.message}", e)
        }

    private fun JsonObject.isSpdx3(): Boolean =
        SPDX3_CONTEXT_REGEX.containsMatchIn(get("@context").toString()) ||
            (get("@graph") as? JsonArray)?.any { (it as? JsonObject)?.string("type") == "SpdxDocument" } == true
}

/** Return the beginning of this content as a string for format detection. */
private fun ByteArray.head(): String = decodeToString(0, minOf(size, HEAD_SIZE)).removePrefix("﻿")
