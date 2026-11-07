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

import java.time.Instant

import org.cyclonedx.model.Bom
import org.cyclonedx.model.Component
import org.cyclonedx.model.ExternalReference
import org.cyclonedx.model.LicenseItem.LicenseItemType
import org.cyclonedx.model.license.Acknowledgement
import org.cyclonedx.parsers.JsonParser
import org.cyclonedx.parsers.XmlParser

/** Regular expressions to find metadata values; group 2 is the value, groups 1 and 3 are kept on removal. */
private val JSON_TIMESTAMP_REGEX = Regex("""("timestamp"\s*:\s*)"([^"]*)"(\s*[,}])""")
private val XML_TIMESTAMP_REGEX = Regex("""(<(?:\w+:)?timestamp>)([^<]*)(</(?:\w+:)?timestamp>)""")
private val JSON_SERIAL_NUMBER_REGEX = Regex("""("serialNumber"\s*:\s*)"([^"]*)"(\s*[,}])""")
private val XML_SERIAL_NUMBER_REGEX = Regex("""(\s)serialNumber\s*=\s*"([^"]*)"(\s|/?>)""")
private val SERIAL_NUMBER_REGEX = Regex("""^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$""")

/** A regular expression to extract the specification version from the namespace of a CycloneDX XML document. */
private val XML_NAMESPACE_REGEX = """http://cyclonedx\.org/schema/bom/(\d+\.\d+)""".toRegex()

/**
 * A parser for CycloneDX documents in JSON or XML format, of any specification version supported by the CycloneDX
 * core library.
 */
internal object CycloneDxParser {
    /** The scope CycloneDX assumes for components that do not declare one. */
    private const val DEFAULT_CYCLONEDX_SCOPE = "required"

    fun parse(content: ByteArray, format: SbomFormat): SbomDocument {
        val bom = runCatching { parseBom(content, format) }.getOrElse { error ->
            // Tools sometimes write invalid metadata that is irrelevant for the ingestion, such as placeholder
            // timestamps. Retry without such values before rejecting the whole document.
            val (sanitized, removed) = content.withoutInvalidMetadata(format)
            if (removed.isEmpty()) throw error.toParseException(format)

            val bom = runCatching { parseBom(sanitized, format) }.getOrElse { throw error.toParseException(format) }
            return BomConverter(bom, format, content).convert().let { document ->
                document.copy(
                    warnings = document.warnings + "Ignored the invalid metadata ${removed.joinToString()} of the BOM."
                )
            }
        }

        return BomConverter(bom, format, content).convert()
    }

    private fun parseBom(content: ByteArray, format: SbomFormat): Bom =
        if (format == SbomFormat.CYCLONEDX_XML) XmlParser().parse(content) else JsonParser().parse(content)

    private fun Throwable.toParseException(format: SbomFormat): SbomParseException =
        this as? SbomParseException ?: SbomParseException("Invalid ${format.displayName} document: $message", this)

    /**
     * Return a copy of this content without metadata values that cannot be interpreted, together with the names of the
     * removed values. Only the timestamp and the serial number are considered, which do not affect the ingestion.
     */
    private fun ByteArray.withoutInvalidMetadata(format: SbomFormat): Pair<ByteArray, List<String>> {
        var text = decodeToString()
        val removed = mutableListOf<String>()

        val isXml = format == SbomFormat.CYCLONEDX_XML

        // In JSON, invalid values are replaced by null; in XML, the timestamp element and the serial number attribute
        // are removed.
        fun MatchResult.removed(removeAll: Boolean): String =
            when {
                !isXml -> groupValues[1] + "null" + groupValues[3]
                removeAll -> ""
                else -> groupValues[1] + groupValues[3]
            }

        val timestampRegex = if (isXml) XML_TIMESTAMP_REGEX else JSON_TIMESTAMP_REGEX
        timestampRegex.find(text)?.takeUnless { runCatching { Instant.parse(it.groupValues[2]) }.isSuccess }?.let {
            text = text.replaceRange(it.range, it.removed(removeAll = true))
            removed += "timestamp"
        }

        val serialNumberRegex = if (isXml) XML_SERIAL_NUMBER_REGEX else JSON_SERIAL_NUMBER_REGEX
        serialNumberRegex.find(text)?.takeUnless { SERIAL_NUMBER_REGEX.matches(it.groupValues[2]) }?.let {
            text = text.replaceRange(it.range, it.removed(removeAll = false))
            removed += "serial number"
        }

        return text.toByteArray() to removed
    }

    private class BomConverter(private val bom: Bom, private val format: SbomFormat, private val content: ByteArray) {
        private val components = linkedMapOf<String, SbomComponent>()
        private val relationships = linkedMapOf<String, MutableList<SbomRelationship>>()
        private val warnings = mutableListOf<String>()
        private var syntheticRefCount = 0

        fun convert(): SbomDocument {
            val rootComponent = bom.metadata?.component
            val rootRef = rootComponent?.let { addComponent(it, parentRef = null) }

            bom.components.orEmpty().forEach { addComponent(it, parentRef = null) }

            bom.dependencies.orEmpty().forEach { dependency ->
                val ref = dependency.ref ?: return@forEach
                dependency.dependencies.orEmpty().mapNotNull { it.ref }.forEach { target ->
                    addRelationship(ref, target)
                }
            }

            return SbomDocument(
                format = format,
                specVersion = bom.specVersion ?: specVersionFromNamespace(),
                name = rootComponent?.let { listOfNotNull(it.group, it.name, it.version).joinToString(":") },
                serialNumber = bom.serialNumber,
                creators = creators(),
                roots = listOfNotNull(rootRef),
                components = components,
                relationships = relationships,
                defaultScope = DEFAULT_CYCLONEDX_SCOPE,
                warnings = warnings
            )
        }

        /**
         * Add the given [component] and recursively its nested components, which become relationships of their
         * [parentRef]. Return the ref under which the component was added.
         */
        private fun addComponent(component: Component, parentRef: String?): String {
            val ref = component.bomRef?.takeUnless { it.isBlank() } ?: "component-${++syntheticRefCount}"

            if (ref in components) {
                if (components[ref]?.name != component.name.orEmpty()) {
                    warnings += "The bom-ref '$ref' is used by multiple components; only the first one is used."
                }
            } else {
                components[ref] = component.toSbomComponent(ref)
            }

            parentRef?.let { addRelationship(it, ref) }
            component.components.orEmpty().forEach { addComponent(it, ref) }

            return ref
        }

        private fun addRelationship(source: String, target: String) {
            val targets = relationships.getOrPut(source) { mutableListOf() }
            if (targets.none { it.target == target }) targets += SbomRelationship(target)
        }

        private fun creators(): List<String> {
            val metadata = bom.metadata ?: return emptyList()

            val legacyTools = metadata.tools.orEmpty().map { tool ->
                listOfNotNull(tool.vendor, tool.name, tool.version).joinToString(" ")
            }

            val toolComponents = metadata.toolChoice?.components.orEmpty().map { tool ->
                listOfNotNull(tool.group, tool.name, tool.version).joinToString(" ")
            }

            val toolServices = metadata.toolChoice?.services.orEmpty().mapNotNull { it.name }

            val authors = metadata.authors.orEmpty().mapNotNull { it.name ?: it.email }

            return (legacyTools + toolComponents + toolServices + authors).filter { it.isNotBlank() }.distinct()
        }

        private fun specVersionFromNamespace(): String {
            val head = content.decodeToString(0, minOf(content.size, HEAD_SIZE))
            return XML_NAMESPACE_REGEX.find(head)?.groupValues?.get(1).orEmpty()
        }
    }
}

/** The number of bytes inspected at the start of a document to determine its properties. */
internal const val HEAD_SIZE = 16 * 1024

private fun Component.toSbomComponent(ref: String): SbomComponent {
    val licenseItems = licenses?.items.orEmpty()

    fun licenseOf(type: LicenseItemType?, item: org.cyclonedx.model.LicenseItem): Pair<String?, Acknowledgement?> =
        when (type) {
            LicenseItemType.LICENSE -> (item.license?.id ?: item.license?.name) to item.license?.acknowledgement

            LicenseItemType.EXPRESSION -> item.expression?.value to item.expression?.acknowledgement

            LicenseItemType.EXPRESSION_DETAILED ->
                item.expressionDetailed?.expression to item.expressionDetailed?.acknowledgement

            else -> null to null
        }

    val licensesWithAcknowledgement = licenseItems.mapNotNull { item ->
        val (license, acknowledgement) = licenseOf(item.type, item)
        license?.takeUnless { it.isBlank() }?.let { it.trim() to acknowledgement }
    }

    val concluded = licensesWithAcknowledgement.filter { it.second == Acknowledgement.CONCLUDED }.map { it.first }
    val declared = licensesWithAcknowledgement.filter { it.second != Acknowledgement.CONCLUDED }.map { it.first }

    @Suppress("DEPRECATION")
    val legacyAuthor = author

    return SbomComponent(
        ref = ref,
        name = name.orEmpty(),
        group = group?.takeUnless { it.isBlank() },
        version = version?.takeUnless { it.isBlank() },
        purl = purl?.takeUnless { it.isBlank() },
        cpe = cpe?.takeUnless { it.isBlank() },
        type = type?.typeName,
        scope = scope?.scopeName,
        description = description?.takeUnless { it.isBlank() },
        declaredLicenses = declared.toSet(),
        concludedLicense = concluded.takeUnless { it.isEmpty() }?.joinToString(" AND ") {
            if (concluded.size > 1 && ' ' in it) "($it)" else it
        },
        copyright = copyright?.takeUnless { it.isBlank() },
        authors = (authors.orEmpty().mapNotNull { it.name ?: it.email } + listOfNotNull(legacyAuthor))
            .filterTo(mutableSetOf()) { it.isNotBlank() },
        supplier = (supplier?.name ?: manufacturer?.name ?: publisher)?.takeUnless { it.isBlank() },
        homepageUrl = externalReferenceUrl(ExternalReference.Type.WEBSITE),
        vcsUrl = externalReferenceUrl(ExternalReference.Type.VCS),
        downloadUrl = externalReferenceUrl(ExternalReference.Type.DISTRIBUTION),
        sourceDownloadUrl = externalReferenceUrl(ExternalReference.Type.SOURCE_DISTRIBUTION),
        hashes = hashes.orEmpty().mapNotNull { hash ->
            val algorithm = hash.algorithm?.takeUnless { it.isBlank() } ?: return@mapNotNull null
            val value = hash.value?.takeUnless { it.isBlank() } ?: return@mapNotNull null
            SbomHash(normalizeHashAlgorithm(algorithm), value.lowercase())
        }
    )
}

private fun Component.externalReferenceUrl(type: ExternalReference.Type): String? =
    externalReferences.orEmpty().firstOrNull { it.type == type && !it.url.isNullOrBlank() }?.url

/**
 * Normalize the name of a hash [algorithm] to upper case without separators, so that for instance "SHA-256",
 * "sha256", and "SHA_256" all become "SHA256".
 */
internal fun normalizeHashAlgorithm(algorithm: String): String =
    algorithm.uppercase().filter { it.isLetterOrDigit() }
