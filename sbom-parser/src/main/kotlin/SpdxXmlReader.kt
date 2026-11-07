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

import java.io.ByteArrayInputStream

import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.ParserConfigurationException

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

import org.w3c.dom.Element
import org.xml.sax.SAXException

/**
 * A reader for SPDX 2.x documents in the XML format. This format mirrors the JSON format: elements correspond to
 * properties, and repeated elements to arrays. The reader converts the document to the JSON tree structure, so that it
 * can be processed by [Spdx2Parser], which treats single values like arrays with one element where arrays are expected.
 */
internal object SpdxXmlReader {
    fun read(content: ByteArray): JsonObject {
        val document = try {
            newDocumentBuilderFactory().newDocumentBuilder().parse(ByteArrayInputStream(content))
        } catch (e: SAXException) {
            throw SbomParseException("Invalid SPDX XML document: ${e.message}", e)
        }

        return document.documentElement.toJson() as? JsonObject
            ?: throw SbomParseException("The SPDX XML document is empty.")
    }

    private fun Element.toJson(): JsonElement {
        val children = childNodes.let { nodes -> (0 until nodes.length).map(nodes::item) }
            .filterIsInstance<Element>()

        if (children.isEmpty()) return JsonPrimitive(textContent.trim())

        return JsonObject(
            children.groupBy { it.localName ?: it.tagName }.mapValues { (_, elements) ->
                if (elements.size == 1) elements.single().toJson() else JsonArray(elements.map { it.toJson() })
            }
        )
    }
}

/**
 * Return a [DocumentBuilderFactory] that is protected against XML external entity (XXE) attacks, as documents are
 * provided by users.
 */
internal fun newDocumentBuilderFactory(): DocumentBuilderFactory =
    DocumentBuilderFactory.newInstance().apply {
        try {
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        } catch (e: ParserConfigurationException) {
            throw IllegalStateException("The XML parser cannot be configured securely.", e)
        }

        isExpandEntityReferences = false
        isXIncludeAware = false
        isNamespaceAware = true
    }
