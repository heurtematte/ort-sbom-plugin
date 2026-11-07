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

/** The SPDX 3 element types of packages, including the profile-specific specializations. */
private val PACKAGE_TYPES = setOf("software_Package", "ai_AIPackage", "dataset_DatasetPackage")

/** The SPDX 3 element types that represent a collection of elements with root elements. */
private val COLLECTION_TYPES = setOf("SpdxDocument", "software_Sbom", "Bom", "Bundle")

/** The SPDX 3 relationship types that express a dependency or containment, associated with the scope they imply. */
private val DEPENDENCY_RELATIONSHIPS = mapOf(
    "dependsOn" to null,
    "contains" to null,
    "hasDynamicLink" to null,
    "hasStaticLink" to null,
    "hasPrerequisite" to null,
    "hasOptionalDependency" to "optional",
    "hasProvidedDependency" to "provided",
    "hasOptionalComponent" to "optional"
)

/** The prefix of the IRIs of licenses on the SPDX license list. */
private const val LICENSE_LIST_PREFIX = "https://spdx.org/licenses/"

/**
 * A parser for SPDX 3.0 documents in the JSON-LD serialization. It supports the compact property and type names
 * defined by the official SPDX 3 JSON-LD context, as well as fully qualified type IRIs.
 */
internal object Spdx3Parser {
    fun parse(document: JsonObject): SbomDocument {
        // JSON-LD allows a document to be a single element instead of a graph, and elements to be nested inline, such as
        // the creation info, so collect the elements from the whole document.
        val graph = mutableListOf<JsonObject>().also { collectElements(document["@graph"] ?: document, it) }
        val elements = linkedMapOf<String, JsonObject>()
        graph.forEach { element -> element.id()?.let { elements.putIfAbsent(it, element) } }

        val warnings = mutableListOf<String>()
        val packages = graph.filter { it.elementType() in PACKAGE_TYPES && it.id() != null }

        val relationshipElements = graph.filter { it.elementType()?.endsWith("Relationship") == true }
        val licenses = mutableMapOf<String, Pair<MutableList<String>, MutableList<String>>>()
        val relationships = linkedMapOf<String, MutableList<SbomRelationship>>()
        val roots = mutableListOf<String>()

        relationshipElements.forEach { relationship ->
            val from = relationship["from"]?.let { (it as? JsonObject)?.id() ?: it.stringValue() } ?: return@forEach
            val type = relationship.string("relationshipType")?.substringAfterLast('/') ?: return@forEach
            val targets = relationship.array("to").mapNotNull { (it as? JsonObject)?.id() ?: it.stringValue() }

            when (type) {
                "hasDeclaredLicense", "hasConcludedLicense" -> {
                    val expressions = targets.mapNotNull { licenseExpression(it, elements) }
                    val (declared, concluded) = licenses.getOrPut(from) { mutableListOf<String>() to mutableListOf() }
                    if (type == "hasDeclaredLicense") declared += expressions else concluded += expressions
                }

                // Collections such as documents describe their roots, while a package describing other packages, as
                // written by some tools for a product, expresses that it is composed of them.
                "describes" -> if (elements[from]?.elementType() in PACKAGE_TYPES) {
                    val edges = relationships.getOrPut(from) { mutableListOf() }
                    targets.filter { it != from && edges.none { edge -> edge.target == it } }
                        .forEach { edges += SbomRelationship(it) }
                } else {
                    roots += targets
                }

                in DEPENDENCY_RELATIONSHIPS -> {
                    val scope = relationship.string("scope")?.substringAfterLast('/')
                        ?: DEPENDENCY_RELATIONSHIPS.getValue(type)
                    val edges = relationships.getOrPut(from) { mutableListOf() }
                    targets.filter { it != from }.forEach { target ->
                        if (edges.none { it.target == target }) edges += SbomRelationship(target, scope)
                    }
                }
            }
        }

        val components = linkedMapOf<String, SbomComponent>()
        packages.forEach { pkg ->
            val ref = pkg.id()!!
            val (declared, concluded) = licenses[ref] ?: (emptyList<String>() to emptyList<String>())
            components.putIfAbsent(ref, pkg.toSbomComponent(ref, elements, declared, concluded))
        }

        // Keep only relationships between packages.
        val packageRelationships = relationships.filterKeys { it in components }.mapValues { (_, edges) ->
            edges.filter { it.target in components }
        }.filterValues { it.isNotEmpty() }

        val spdxDocument = graph.firstOrNull { it.elementType() == "SpdxDocument" }
        spdxDocument?.let { roots += resolveRoots(it, elements, mutableSetOf()) }
        if (spdxDocument == null) {
            graph.filter { it.elementType() in COLLECTION_TYPES }.forEach {
                roots += resolveRoots(it, elements, mutableSetOf())
            }
        }

        val packageRoots = roots.distinct().filter { it in components }
        val creationInfo = graph.firstOrNull { it.elementType() == "CreationInfo" }
            ?: (spdxDocument?.get("creationInfo") as? JsonObject)

        if (components.isEmpty()) warnings += "The document does not contain any packages."

        return SbomDocument(
            format = SbomFormat.SPDX3_JSON_LD,
            specVersion = creationInfo?.string("specVersion")?.let { "SPDX-$it" } ?: "SPDX-3",
            name = spdxDocument?.string("name"),
            serialNumber = spdxDocument?.id(),
            creators = creationInfo?.let { info ->
                (info.array("createdBy") + info.array("createdUsing")).mapNotNull { agent ->
                    val id = (agent as? JsonObject)?.id() ?: agent.stringValue()
                    id?.let { elements[it]?.string("name") ?: it }
                }
            }.orEmpty(),
            roots = packageRoots,
            components = components,
            relationships = packageRelationships,
            warnings = warnings
        )
    }

    /**
     * Return the root elements of the given [collection], descending into nested collections such as an SBOM that is
     * the root element of an SPDX document.
     */
    private fun resolveRoots(
        collection: JsonObject,
        elements: Map<String, JsonObject>,
        visited: MutableSet<String>
    ): List<String> =
        collection.array("rootElement").mapNotNull { (it as? JsonObject)?.id() ?: it.stringValue() }.flatMap { root ->
            val element = elements[root]
            if (element?.elementType() in COLLECTION_TYPES && visited.add(root)) {
                resolveRoots(element!!, elements, visited)
            } else {
                listOf(root)
            }
        }

    private fun JsonObject.toSbomComponent(
        ref: String,
        elements: Map<String, JsonObject>,
        declaredLicenses: List<String>,
        concludedLicenses: List<String>
    ): SbomComponent {
        val identifiers = array("externalIdentifier").filterIsInstance<JsonObject>()

        fun identifier(vararg types: String): String? =
            identifiers.firstOrNull { it.string("externalIdentifierType")?.substringAfterLast('/') in types }
                ?.string("identifier")

        val externalRefs = array("externalRef").filterIsInstance<JsonObject>()
        val vcsRef = externalRefs.firstOrNull { it.string("externalRefType")?.substringAfterLast('/') == "vcs" }
            ?.array("locator")?.firstNotNullOfOrNull { it.stringValue() }

        val downloadLocation = string("software_downloadLocation")?.takeUnless { it.uppercase() in NO_ASSERTION }
        val downloadIsVcs = downloadLocation?.isVcsLocation() == true

        fun agentName(value: JsonElement): String? =
            (value as? JsonObject)?.string("name") ?: value.stringValue()?.let { elements[it]?.string("name") }

        return SbomComponent(
            ref = ref,
            name = string("name").orEmpty(),
            version = string("software_packageVersion"),
            purl = string("software_packageUrl") ?: identifier("packageUrl"),
            cpe = identifier("cpe23", "cpe22"),
            type = string("software_primaryPurpose")?.substringAfterLast('/')?.lowercase(),
            description = (string("description") ?: string("summary"))?.takeUnless { it.isBlank() },
            declaredLicenses = declaredLicenses.toSet(),
            concludedLicense = concludedLicenses.takeUnless { it.isEmpty() }?.joinToString(" AND "),
            copyright = string("software_copyrightText")?.takeUnless { it.uppercase() in NO_ASSERTION },
            authors = array("originatedBy").mapNotNullTo(mutableSetOf()) { agentName(it) },
            supplier = get("suppliedBy")?.let { agentName(it) },
            homepageUrl = string("software_homePage"),
            vcsUrl = vcsRef ?: downloadLocation.takeIf { downloadIsVcs },
            sourceDownloadUrl = downloadLocation.takeUnless { downloadIsVcs },
            hashes = array("verifiedUsing").filterIsInstance<JsonObject>().mapNotNull { hash ->
                val algorithm = hash.string("algorithm")?.substringAfterLast('/') ?: return@mapNotNull null
                val value = hash.string("hashValue") ?: return@mapNotNull null
                SbomHash(normalizeHashAlgorithm(algorithm), value.lowercase())
            }
        )
    }

    /**
     * Return the SPDX license expression represented by the license element with the given [id], or *null* if it
     * does not represent a license.
     */
    private fun licenseExpression(id: String, elements: Map<String, JsonObject>, depth: Int = 0): String? {
        if (depth > MAX_LICENSE_DEPTH) return null

        val element = elements[id]
            ?: return id.takeIf { it.startsWith(LICENSE_LIST_PREFIX) }?.removePrefix(LICENSE_LIST_PREFIX)
                ?: id.substringAfterLast('/').takeIf { it.startsWith("LicenseRef-") }

        fun member(key: String): String? =
            element[key]?.let { (it as? JsonObject)?.id() ?: it.stringValue() }?.let {
                licenseExpression(it, elements, depth + 1)
            }

        fun members(operator: String): String? =
            element.array("expandedlicensing_member")
                .mapNotNull { (it as? JsonObject)?.id() ?: it.stringValue() }
                .mapNotNull { licenseExpression(it, elements, depth + 1) }
                .takeUnless { it.isEmpty() }
                ?.joinToString(" $operator ") { if (' ' in it) "($it)" else it }

        return when (element.elementType()) {
            "simplelicensing_LicenseExpression" -> element.string("simplelicensing_licenseExpression")

            "expandedlicensing_ListedLicense" -> id.substringAfterLast('/')

            "expandedlicensing_CustomLicense" ->
                id.substringAfterLast('/').substringAfterLast('#').takeIf { it.startsWith("LicenseRef-") }
                    ?: element.string("name")

            "expandedlicensing_ConjunctiveLicenseSet" -> members("AND")

            "expandedlicensing_DisjunctiveLicenseSet" -> members("OR")

            "expandedlicensing_OrLaterOperator" -> member("expandedlicensing_subjectLicense")?.let { "$it+" }

            "expandedlicensing_WithAdditionOperator" -> {
                val license = member("expandedlicensing_subjectExtendableLicense")
                val addition = element["expandedlicensing_subjectAddition"]?.let {
                    ((it as? JsonObject)?.id() ?: it.stringValue())?.substringAfterLast('/')
                }
                license?.let { if (addition != null) "$it WITH $addition" else it }
            }

            else -> null
        }?.takeUnless { it.isBlank() || it.uppercase() in NO_ASSERTION }
    }

    private const val MAX_LICENSE_DEPTH = 16

    private val NO_ASSERTION = setOf("NOASSERTION", "NONE")
}

/** Recursively collect all objects with a type below the given [element] into [elements]. */
private fun collectElements(element: JsonElement, elements: MutableList<JsonObject>) {
    when (element) {
        is JsonObject -> {
            if (element.elementType() != null) elements += element
            element.forEach { (key, value) -> if (key != "@context") collectElements(value, elements) }
        }

        is JsonArray -> element.forEach { collectElements(it, elements) }

        else -> Unit
    }
}

/** Return the identifier of this SPDX 3 element. */
private fun JsonObject.id(): String? = string("spdxId") ?: string("@id")

/**
 * Return the type of this SPDX 3 element in the compact form of the JSON-LD context, such as "software_Package",
 * also if it is given as a prefixed name or as a full IRI.
 */
private fun JsonObject.elementType(): String? {
    val type = string("type") ?: string("@type") ?: return null

    val iriPath = type.substringAfter("/terms/", missingDelimiterValue = "")
    if (iriPath.isNotEmpty()) {
        val namespace = iriPath.substringBefore('/')
        val name = iriPath.substringAfter('/')
        return if (namespace == "Core") name else "${namespace.lowercase().replace(" ", "")}_$name"
    }

    return type.replace(':', '_')
}
