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

package org.eclipse.apoapsis.sbom.packagemanager

import org.eclipse.apoapsis.sbom.parser.SbomComponent
import org.eclipse.apoapsis.sbom.parser.SbomDocument
import org.eclipse.apoapsis.sbom.parser.SbomRelationship

import org.ossreviewtoolkit.model.utils.toPackageUrl

/** The type of CycloneDX components, and the primary purpose of SPDX packages, that represent a single file. */
private const val FILE_COMPONENT_TYPE = "file"

/**
 * Return whether this component is a file without a valid package URL, such as the files of a container image that
 * SBOMs created by tools like Syft list. Advisors cannot identify such a file, and the scanner cannot download it.
 */
internal fun SbomComponent.isFileWithoutPackageUrl(): Boolean =
    type == FILE_COMPONENT_TYPE && purl.toPackageUrl() == null

/**
 * Return this document without the components that match the given [predicate], except for its roots. Relationships
 * to a removed component are replaced by relationships to the components that it depends on or contains, with the
 * scope of the replaced relationship if it has one, so that these components keep their place in the dependency graph.
 */
internal fun SbomDocument.withoutComponents(predicate: (SbomComponent) -> Boolean): SbomDocument {
    val removed = components.filter { (ref, component) -> ref !in roots && predicate(component) }.keys
    if (removed.isEmpty()) return this

    fun replace(relationship: SbomRelationship, visited: MutableSet<String>): List<SbomRelationship> =
        when {
            relationship.target !in removed -> listOf(relationship)

            // Removed components that depend on each other in a cycle are only followed once.
            !visited.add(relationship.target) -> emptyList()

            else -> dependenciesOf(relationship.target).flatMap { nested ->
                replace(nested.copy(scope = relationship.scope ?: nested.scope), visited)
            }
        }

    return copy(
        components = components.filterKeys { it !in removed },
        relationships = relationships.filterKeys { it !in removed }.mapValues { (_, outgoing) ->
            val visited = mutableSetOf<String>()
            outgoing.flatMap { replace(it, visited) }.distinct()
        }
    )
}
