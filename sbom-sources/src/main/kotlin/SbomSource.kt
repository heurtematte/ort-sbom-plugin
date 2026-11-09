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

import java.net.URI
import java.net.URISyntaxException

/** The kinds of [SbomSource]s. */
enum class SbomSourceType(
    /** The identifier of the type in source files. */
    val id: String
) {
    /** A project of a Dependency-Track instance. */
    DEPENDENCY_TRACK("dependency-track"),

    /** A component or a product of a sbomify instance. */
    SBOMIFY("sbomify"),

    /** An SBOM document that is downloaded as is. */
    DOCUMENT("document");

    companion object {
        /** Return the type with the given [id], ignoring case. */
        fun forId(id: String): SbomSourceType =
            entries.find { it.id.equals(id.trim(), ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "Unknown SBOM source type '$id'; supported types are ${entries.joinToString { "'${it.id}'" }}."
                )
    }
}

/** A remote location of an SBOM, such as a Dependency-Track project or a sbomify component. */
sealed interface SbomSource {
    /** The URL of the source, as given by the user. */
    val url: String

    /** A human-readable description of the source for messages. */
    val description: String

    /**
     * A project of the Dependency-Track instance at [baseUrl] with the given [uuid], as given by the URL of the project
     * page, such as `https://sbom.eclipse.org/projects/<uuid>`. If a [version] is given, the version of the project
     * with the same name is exported instead; the version [LATEST] selects the version flagged as latest, or, if no
     * version is flagged, the active version whose SBOM was imported last. The API is called at [apiUrl], the URL of
     * the API server of the instance, if it is not served by the frontend at [baseUrl].
     */
    data class DependencyTrackProject(
        val baseUrl: String,
        val uuid: String,
        val version: String? = null,
        val apiUrl: String? = null
    ) : SbomSource {
        override val url = "$baseUrl/projects/$uuid"
        override val description = "Dependency-Track project $uuid at $baseUrl" + version.versionSuffix()

        /** The base URL of the API of the instance, without the path of the API version. */
        val apiBaseUrl: String get() = apiUrl ?: baseUrl
    }

    /**
     * A component of the sbomify instance at [baseUrl] with the given [id], as given by the URL of the component page,
     * such as `https://app.sbomify.com/component/<id>/`. Its latest SBOM is retrieved, or the one with the given
     * [version].
     */
    data class SbomifyComponent(val baseUrl: String, val id: String, val version: String? = null) : SbomSource {
        override val url = "$baseUrl/component/$id/"
        override val description = "sbomify component $id at $baseUrl" + version.versionSuffix()
    }

    /**
     * A product of the sbomify instance at [baseUrl] with the given [id], as given by the URL of the product page, such
     * as `https://app.sbomify.com/product/<id>/`. The aggregated SBOM of its latest state is retrieved.
     */
    data class SbomifyProduct(val baseUrl: String, val id: String) : SbomSource {
        override val url = "$baseUrl/product/$id/"
        override val description = "sbomify product $id at $baseUrl"
    }

    /** An SBOM document at the given [url]. */
    data class Document(override val url: String) : SbomSource {
        override val description = url
    }

    companion object {
        /** The version that selects the latest version of a Dependency-Track project or a sbomify component. */
        const val LATEST = "latest"

        private const val UUID_PATTERN = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

        private val DEPENDENCY_TRACK_REGEX = Regex("""^(https?://[^?#]+?)/projects/($UUID_PATTERN)/?(?:[?#].*)?$""")

        private val SBOMIFY_REGEX =
            Regex("""^(https?://[^?#]+?)/(?:public/)?(component|product)/([A-Za-z0-9_-]+)/?(?:[?#].*)?$""")

        /**
         * Return the [SbomSource] for the given [url]. Unless a [type] is given, it is detected from the URL: URLs of
         * Dependency-Track project pages and of sbomify component or product pages are recognized, any other URL is
         * a [Document]. The optional [version] selects a version of a Dependency-Track project or sbomify component.
         * Throw an [IllegalArgumentException] if the URL does not match the type or the version is not supported.
         */
        fun parse(url: String, type: SbomSourceType? = null, version: String? = null): SbomSource {
            val trimmedUrl = url.trim()
            requireHttpUrl(trimmedUrl)

            val trimmedVersion = version?.trim()?.takeUnless { it.isEmpty() }
            val dependencyTrackMatch = DEPENDENCY_TRACK_REGEX.matchEntire(trimmedUrl)
            val sbomifyMatch = SBOMIFY_REGEX.matchEntire(trimmedUrl)

            val source = when (type ?: detectType(dependencyTrackMatch, sbomifyMatch)) {
                SbomSourceType.DEPENDENCY_TRACK -> {
                    requireNotNull(dependencyTrackMatch) {
                        "'$trimmedUrl' is not the URL of a Dependency-Track project page, such as " +
                            "'https://<host>/projects/<uuid>'."
                    }

                    DependencyTrackProject(
                        dependencyTrackMatch.groupValues[1],
                        dependencyTrackMatch.groupValues[2],
                        trimmedVersion
                    )
                }

                SbomSourceType.SBOMIFY -> {
                    requireNotNull(sbomifyMatch) {
                        "'$trimmedUrl' is not the URL of a sbomify component or product page, such as " +
                            "'https://<host>/component/<id>/'."
                    }

                    val (baseUrl, kind, id) = sbomifyMatch.destructured
                    if (kind == "product") {
                        require(trimmedVersion == null || trimmedVersion == LATEST) {
                            "sbomify products are retrieved in their latest state; a version cannot be selected."
                        }

                        SbomifyProduct(baseUrl, id)
                    } else {
                        SbomifyComponent(baseUrl, id, trimmedVersion)
                    }
                }

                SbomSourceType.DOCUMENT -> {
                    require(trimmedVersion == null) {
                        "A version can only be selected for Dependency-Track projects and sbomify components, not " +
                            "for the document '$trimmedUrl'."
                    }

                    Document(trimmedUrl)
                }
            }

            return source
        }

        private fun detectType(dependencyTrackMatch: MatchResult?, sbomifyMatch: MatchResult?): SbomSourceType =
            when {
                dependencyTrackMatch != null -> SbomSourceType.DEPENDENCY_TRACK
                sbomifyMatch != null -> SbomSourceType.SBOMIFY
                else -> SbomSourceType.DOCUMENT
            }

        private fun requireHttpUrl(url: String) {
            val uri = try {
                URI(url)
            } catch (e: URISyntaxException) {
                throw IllegalArgumentException("'$url' is not a valid URL: ${e.message}", e)
            }

            require(uri.scheme?.lowercase() in setOf("http", "https") && !uri.host.isNullOrEmpty()) {
                "'$url' is not an HTTP or HTTPS URL."
            }
        }
    }
}

private fun String?.versionSuffix(): String = this?.let { " (version '$it')" }.orEmpty()
