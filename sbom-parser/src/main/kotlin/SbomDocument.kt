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

/**
 * The serialization formats of SBOMs that can be ingested. Each format has a [displayName], the [mediaType] to use
 * when serving a document in this format, and a [fileExtension] that tools recognize for it.
 */
enum class SbomFormat(val displayName: String, val mediaType: String, val fileExtension: String) {
    CYCLONEDX_JSON("CycloneDX JSON", "application/vnd.cyclonedx+json", "cdx.json"),
    CYCLONEDX_XML("CycloneDX XML", "application/vnd.cyclonedx+xml", "cdx.xml"),
    SPDX_JSON("SPDX JSON", "application/spdx+json", "spdx.json"),
    SPDX_YAML("SPDX YAML", "application/spdx+yaml", "spdx.yaml"),
    SPDX_TAG_VALUE("SPDX tag-value", "text/spdx", "spdx"),
    SPDX_XML("SPDX XML", "application/spdx+xml", "spdx.xml"),
    SPDX3_JSON_LD("SPDX 3 JSON-LD", "application/spdx+json", "spdx3.json");

    /** Whether this is one of the CycloneDX formats. */
    val isCycloneDx: Boolean get() = this == CYCLONEDX_JSON || this == CYCLONEDX_XML
}

/**
 * A format-independent representation of an SBOM: the components it lists and the relationships between them.
 *
 * Components are identified by their [ref][SbomComponent.ref], which is the `bom-ref` for CycloneDX and the SPDX ID
 * for SPDX. The [roots] are the refs of the components the SBOM describes, such as the CycloneDX `metadata.component`
 * or the packages an SPDX document `DESCRIBES`; there may be none.
 */
data class SbomDocument(
    /** The format of the parsed document. */
    val format: SbomFormat,

    /** The version of the specification, such as "1.6" for CycloneDX or "SPDX-2.3" for SPDX. */
    val specVersion: String,

    /** The name of the document, if any. */
    val name: String? = null,

    /** A unique identifier of the document, such as the CycloneDX serial number or the SPDX document namespace. */
    val serialNumber: String? = null,

    /** The tools or persons that created the document. */
    val creators: List<String> = emptyList(),

    /** The refs of the root components described by the document. */
    val roots: List<String> = emptyList(),

    /** All components of the document, associated by their refs, in document order. */
    val components: Map<String, SbomComponent> = emptyMap(),

    /** The outgoing relationships of components, associated by the ref of the source component. */
    val relationships: Map<String, List<SbomRelationship>> = emptyMap(),

    /** The name of the scope to use for dependencies of root components that do not define one themselves. */
    val defaultScope: String = DEFAULT_SCOPE,

    /** Problems found while parsing the document that did not prevent it from being parsed. */
    val warnings: List<String> = emptyList()
) {
    companion object {
        /** The default scope name for dependencies whose scope is unknown. */
        const val DEFAULT_SCOPE = "dependencies"
    }

    /** Return the refs of the components that the component with the given [ref] depends on or contains. */
    fun dependenciesOf(ref: String): List<SbomRelationship> = relationships[ref].orEmpty()
}

/**
 * A relationship of a component to the component with the [target] ref, which is either a dependency or a contained
 * component. An optional [scope] qualifies the relationship, such as "build" or "test".
 */
data class SbomRelationship(
    val target: String,
    val scope: String? = null
)

/**
 * A component (CycloneDX) or package (SPDX) of an SBOM.
 */
data class SbomComponent(
    /** The identifier of the component within its document. */
    val ref: String,

    /** The name of the component. */
    val name: String,

    /** The group or namespace of the component, if any. */
    val group: String? = null,

    /** The version of the component, if any. */
    val version: String? = null,

    /** The package URL of the component, if any. */
    val purl: String? = null,

    /** The CPE of the component, if any. */
    val cpe: String? = null,

    /** The type or purpose of the component, such as "library" or "application", in lower case. */
    val type: String? = null,

    /** The scope of the component, if the format supports it, such as "required" or "optional" for CycloneDX. */
    val scope: String? = null,

    /** A description of the component. */
    val description: String? = null,

    /** The licenses declared by the component, as SPDX expressions or license names. */
    val declaredLicenses: Set<String> = emptySet(),

    /** The license concluded for the component as an SPDX expression, if any. */
    val concludedLicense: String? = null,

    /** The copyright statement of the component, if any. */
    val copyright: String? = null,

    /** The authors of the component. */
    val authors: Set<String> = emptySet(),

    /** The supplier of the component, if any. */
    val supplier: String? = null,

    /** The URL of the homepage of the component, if any. */
    val homepageUrl: String? = null,

    /** The URL of the version control repository of the component, if any. */
    val vcsUrl: String? = null,

    /** The URL from which the component can be downloaded, if any. */
    val downloadUrl: String? = null,

    /** The URL from which the source code of the component can be downloaded, if any. */
    val sourceDownloadUrl: String? = null,

    /** The hashes of the component. */
    val hashes: List<SbomHash> = emptyList()
)

/**
 * A hash [value] computed with the given [algorithm], whose name is normalized to upper case without separators, such
 * as "SHA256".
 */
data class SbomHash(
    val algorithm: String,
    val value: String
)

/**
 * An exception thrown if a document cannot be parsed as an SBOM.
 */
class SbomParseException(message: String, cause: Throwable? = null) : Exception(message, cause)
