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

/** An entry of an SBOM source file: a [source], and [project] metadata for the projects its SBOM describes. */
data class SbomSourceEntry(
    /** The source to retrieve the SBOM from. */
    val source: SbomSource,

    /** Metadata of the projects described by the SBOM of the [source], which takes precedence over the SBOM. */
    val project: SbomProjectMetadata = SbomProjectMetadata.EMPTY
)

/**
 * Metadata of the projects described by an SBOM, for metadata that the SBOM lacks or that is not accurate, such as the
 * licenses of a product. Each given value replaces the corresponding value of the SBOM.
 */
data class SbomProjectMetadata(
    /** The description of the projects. */
    val description: String? = null,

    /** The URL of the homepage of the projects. */
    val homepageUrl: String? = null,

    /** The authors of the projects. */
    val authors: Set<String> = emptySet(),

    /** The licenses declared by the projects, as SPDX expressions or license names. */
    val declaredLicenses: Set<String> = emptySet()
) {
    companion object {
        /** Metadata without any values. */
        val EMPTY = SbomProjectMetadata()
    }

    /** Return whether no value is given. */
    fun isEmpty(): Boolean = this == EMPTY
}
