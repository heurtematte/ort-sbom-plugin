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

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** The SPDX ID of the document element. */
private const val DOCUMENT_ID = "SPDXRef-DOCUMENT"

/** Values used by SPDX to express that no information is available. */
private val NO_VALUES = setOf("NOASSERTION", "NONE")

/**
 * The SPDX 2 relationship types that express a dependency or containment, associated with the direction of the edge
 * (*true* if the related element depends on the element, i.e. the edge has to be reversed) and the scope it implies.
 */
private val DEPENDENCY_RELATIONSHIPS = mapOf(
    "DEPENDS_ON" to (false to null),
    "DEPENDENCY_OF" to (true to null),
    "CONTAINS" to (false to null),
    "CONTAINED_BY" to (true to null),
    "DYNAMIC_LINK" to (false to null),
    "STATIC_LINK" to (false to null),
    "HAS_PREREQUISITE" to (false to null),
    "PREREQUISITE_FOR" to (true to null),
    "BUILD_DEPENDENCY_OF" to (true to "build"),
    "DEV_DEPENDENCY_OF" to (true to "dev"),
    "TEST_DEPENDENCY_OF" to (true to "test"),
    "RUNTIME_DEPENDENCY_OF" to (true to "runtime"),
    "OPTIONAL_DEPENDENCY_OF" to (true to "optional"),
    "PROVIDED_DEPENDENCY_OF" to (true to "provided"),
    "OPTIONAL_COMPONENT_OF" to (true to "optional")
)

/**
 * A lenient parser for SPDX 2.x documents. It works on the JSON tree of the document, so it supports the JSON format
 * directly, and the YAML and tag-value formats after they have been converted to the same tree structure.
 *
 * In contrast to a strict model, the parser does not reject documents violating constraints of the specification
 * that are irrelevant for the ingestion, such as malformed checksums, since SBOMs found in the wild often do.
 */
internal object Spdx2Parser {
    fun parse(document: JsonObject, format: SbomFormat): SbomDocument {
        val warnings = mutableListOf<String>()
        val components = linkedMapOf<String, SbomComponent>()

        document.array("packages").filterIsInstance<JsonObject>().forEach { pkg ->
            val ref = pkg.string("SPDXID")
            if (ref == null) {
                warnings += "Ignoring the package '${pkg.string("name")}' without an SPDX ID."
            } else if (components.putIfAbsent(ref, pkg.toSbomComponent(ref)) != null) {
                warnings += "The SPDX ID '$ref' is used by multiple packages; only the first one is used."
            }
        }

        val roots = mutableListOf<String>()
        document.array("documentDescribes").mapNotNull { it.stringValue() }.forEach { roots += it }

        val relationships = linkedMapOf<String, MutableList<SbomRelationship>>()
        var externalReferences = 0

        document.array("relationships").filterIsInstance<JsonObject>().forEach { relationship ->
            val source = relationship.string("spdxElementId") ?: return@forEach
            val type = relationship.string("relationshipType")?.uppercase()?.replace('-', '_') ?: return@forEach
            val target = relationship.string("relatedSpdxElement") ?: return@forEach

            when {
                type == "DESCRIBES" && source == DOCUMENT_ID -> roots += target

                type == "DESCRIBED_BY" && target == DOCUMENT_ID -> roots += source

                type in DEPENDENCY_RELATIONSHIPS -> {
                    val (reverse, scope) = DEPENDENCY_RELATIONSHIPS.getValue(type)
                    val (from, to) = if (reverse) target to source else source to target

                    if (from.startsWith("DocumentRef-") || to.startsWith("DocumentRef-")) {
                        externalReferences++
                    } else if (from in components && to in components && from != to) {
                        val targets = relationships.getOrPut(from) { mutableListOf() }
                        if (targets.none { it.target == to }) targets += SbomRelationship(to, scope)
                    }
                }
            }
        }

        if (externalReferences > 0) {
            warnings += "Ignoring $externalReferences relationship(s) to elements of external SPDX documents."
        }

        val packageRoots = roots.distinct().filter { it in components }
        if (packageRoots.size < roots.distinct().size) {
            warnings += "Ignoring described elements that are not packages of the document: " +
                (roots.distinct() - packageRoots.toSet()).joinToString()
        }

        val creationInfo = document["creationInfo"] as? JsonObject

        return SbomDocument(
            format = format,
            specVersion = document.string("spdxVersion").orEmpty(),
            name = document.string("name"),
            serialNumber = document.string("documentNamespace"),
            creators = creationInfo?.array("creators")?.mapNotNull { it.stringValue() }.orEmpty(),
            roots = packageRoots,
            components = components,
            relationships = relationships,
            warnings = warnings
        )
    }

    private fun JsonObject.toSbomComponent(ref: String): SbomComponent {
        val externalRefs = array("externalRefs").filterIsInstance<JsonObject>()

        fun externalRef(vararg types: String): String? =
            externalRefs.firstOrNull { ext ->
                ext.string("referenceType")?.lowercase() in types
            }?.string("referenceLocator")

        val downloadLocation = string("downloadLocation")?.takeUnless { it.uppercase() in NO_VALUES }
        val (vcsUrl, downloadUrl) = when {
            downloadLocation == null -> null to null
            downloadLocation.isVcsLocation() -> downloadLocation to null
            else -> null to downloadLocation
        }

        return SbomComponent(
            ref = ref,
            name = string("name").orEmpty(),
            version = string("versionInfo")?.takeUnless { it.uppercase() in NO_VALUES },
            purl = externalRef("purl"),
            cpe = externalRef("cpe23type", "cpe22type"),
            type = string("primaryPackagePurpose")?.lowercase()?.replace('_', '-'),
            description = (string("description") ?: string("summary"))?.takeUnless { it.isBlank() },
            declaredLicenses = setOfNotNull(string("licenseDeclared")?.takeUnless { it.uppercase() in NO_VALUES }),
            concludedLicense = string("licenseConcluded")?.takeUnless { it.uppercase() in NO_VALUES },
            copyright = string("copyrightText")?.takeUnless { it.uppercase() in NO_VALUES || it.isBlank() },
            authors = setOfNotNull(string("originator")?.toAgentName()),
            supplier = string("supplier")?.toAgentName(),
            homepageUrl = string("homepage")?.takeUnless { it.uppercase() in NO_VALUES },
            vcsUrl = vcsUrl,
            sourceDownloadUrl = downloadUrl,
            hashes = array("checksums").filterIsInstance<JsonObject>().mapNotNull { checksum ->
                val algorithm = checksum.string("algorithm") ?: return@mapNotNull null
                val value = checksum.string("checksumValue") ?: return@mapNotNull null
                SbomHash(normalizeHashAlgorithm(algorithm), value.lowercase())
            }
        )
    }
}

/**
 * Return whether this SPDX download location refers to a version control repository, such as
 * `git+https://github.com/org/repo.git@v1.0`.
 */
internal fun String.isVcsLocation(): Boolean =
    VCS_PREFIXES.any { startsWith(it, ignoreCase = true) } || endsWith(".git", ignoreCase = true)

private val VCS_PREFIXES = listOf("git+", "git://", "hg+", "svn+", "bzr+")

/**
 * Return the name of an SPDX agent such as "Organization: Eclipse Foundation (contact@example.org)" or
 * "Person: Jane Doe", or *null* if no agent is specified.
 */
internal fun String.toAgentName(): String? =
    takeUnless { it.uppercase() in NO_VALUES }
        ?.substringAfter(':')
        ?.substringBefore(" (")
        ?.trim()
        ?.takeUnless { it.isEmpty() }

internal fun JsonObject.string(key: String): String? = get(key)?.stringValue()

internal fun JsonObject.array(key: String): List<JsonElement> =
    when (val value = get(key)) {
        is JsonArray -> value
        null -> emptyList()
        else -> listOf(value)
    }

internal fun JsonElement.stringValue(): String? = (this as? JsonPrimitive)?.contentOrNull
