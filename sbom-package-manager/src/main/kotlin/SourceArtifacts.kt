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

import com.github.packageurl.PackageURL

/** The repository of Maven packages whose package URL names no other repository. */
private const val MAVEN_CENTRAL_URL = "https://repo.maven.apache.org/maven2"

/** The registry of npm packages whose package URL names no other registry. */
private const val NPM_REGISTRY_URL = "https://registry.npmjs.org"

/**
 * Return the URL of the source artifact of the package with this package URL, for registries whose layout makes it
 * predictable, or *null* otherwise. Like the package managers of ORT, this is the sources JAR of a Maven package and
 * the tarball of an npm package. The `repository_url` qualifier selects another repository than the public one.
 *
 * The artifact may not exist, for instance if a Maven package was published without sources; the scanner then
 * reports that it could not get the sources, as it would without this URL.
 */
internal fun PackageURL.sourceArtifactUrl(): String? =
    when (type) {
        PackageURL.StandardTypes.MAVEN -> mavenSourcesJarUrl()
        PackageURL.StandardTypes.NPM -> npmTarballUrl()
        else -> null
    }

private fun PackageURL.mavenSourcesJarUrl(): String? {
    val group = namespace?.takeUnless { it.isEmpty() } ?: return null

    // The files of snapshot versions are named after the time they were published at.
    val version = version?.takeUnless { it.isEmpty() || it.endsWith("-SNAPSHOT") } ?: return null

    // Parent POMs and BOMs have no sources.
    if (qualifiers?.get("type") == "pom") return null

    val repository = qualifiers?.get("repository_url")?.trimEnd('/') ?: MAVEN_CENTRAL_URL
    return "$repository/${group.replace('.', '/')}/$name/$version/$name-$version-sources.jar"
}

private fun PackageURL.npmTarballUrl(): String? {
    val version = version?.takeUnless { it.isEmpty() } ?: return null
    val registry = qualifiers?.get("repository_url")?.trimEnd('/') ?: NPM_REGISTRY_URL

    // The namespace of scoped packages is the scope, such as "@types".
    val fullName = listOfNotNull(namespace?.takeUnless { it.isEmpty() }, name).joinToString("/")
    return "$registry/$fullName/-/$name-$version.tgz"
}
