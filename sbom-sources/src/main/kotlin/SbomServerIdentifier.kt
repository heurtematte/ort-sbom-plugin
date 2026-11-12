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

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** The server of an [SbomSource], as identified by [SbomServerIdentifier]. */
data class SbomServer(
    /** The type of the server. */
    val type: SbomSourceType,

    /**
     * The base URL of the API of the server, without the path of the API version. For Dependency-Track, the URL of the
     * API server configured in the frontend, which may differ from the URL of the frontend; *null* for documents.
     */
    val apiUrl: String?,

    /** The version of the server software as reported by the server, if any. */
    val version: String?
)

/** An exception thrown if the server of an [SbomSource] is not of the expected type or cannot be reached. */
class SbomServerIdentificationException(message: String, cause: Throwable? = null) : IOException(message, cause)

/**
 * Identify the servers of [SbomSource]s, so that they are known to be what their URLs suggest before credentials are
 * sent to them. Only the public endpoints that the platforms provide for this purpose are requested, without
 * credentials:
 *
 * - Dependency-Track: the configuration of the frontend, `GET <frontend>/static/config.json`, whose `API_BASE_URL`
 *   gives the API server if it is not served by the frontend, then `GET <api>/api/version`, whose `application` must
 *   be Dependency-Track. Both endpoints exist in Dependency-Track 4 and 5.
 * - sbomify: the OpenAPI description `GET <base>/api/v1/openapi.json`, whose title must be the sbomify API.
 * - Documents are not identified, as a document is not a server.
 *
 * Redirects are only followed within the same host, so that an identification cannot be used to reach other hosts.
 *
 * Requests are retried according to [retryPolicy] if a server is temporarily unavailable. By default, they are only
 * retried twice within a few seconds, as an identification is often requested interactively, for instance when a source
 * is registered.
 */
class SbomServerIdentifier(
    connectTimeout: Duration = Duration.ofSeconds(DEFAULT_CONNECT_TIMEOUT_SECONDS),
    private val requestTimeout: Duration = Duration.ofSeconds(DEFAULT_REQUEST_TIMEOUT_SECONDS),
    retryPolicy: RetryPolicy = RetryPolicy(maxRetries = DEFAULT_MAX_RETRIES)
) {
    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_SECONDS = 10L
        private const val DEFAULT_REQUEST_TIMEOUT_SECONDS = 30L
        private const val DEFAULT_MAX_RETRIES = 2
        private const val MAX_REDIRECTS = 3

        private val DEPENDENCY_TRACK_NAME = Regex("""dependency[- ]?track""", RegexOption.IGNORE_CASE)

        private val json = Json { ignoreUnknownKeys = true }
    }

    private val sender = RetryingSender(
        HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(connectTimeout)
            .build(),
        retryPolicy
    )

    /**
     * Identify the server of the given [source]. Throw an [SbomServerIdentificationException] if it cannot be reached
     * or is not of the type of the source.
     */
    fun identify(source: SbomSource): SbomServer =
        when (source) {
            is SbomSource.DependencyTrackProject -> identifyDependencyTrack(source.baseUrl)
            is SbomSource.SbomifyComponent -> identifySbomify(source.baseUrl)
            is SbomSource.SbomifyProduct -> identifySbomify(source.baseUrl)
            is SbomSource.Document -> SbomServer(SbomSourceType.DOCUMENT, apiUrl = null, version = null)
        }

    private fun identifyDependencyTrack(baseUrl: String): SbomServer {
        val apiUrl = dependencyTrackApiUrl(baseUrl)
        val versionUrl = URI("$apiUrl/api/version")
        val about = getJsonObject(versionUrl)
            ?: throw SbomServerIdentificationException(
                "'$baseUrl' is not a Dependency-Track instance: '$versionUrl' did not return the version of " +
                    "Dependency-Track."
            )

        val application = about.string("application")
        if (application == null || !DEPENDENCY_TRACK_NAME.containsMatchIn(application)) {
            throw SbomServerIdentificationException(
                "'$baseUrl' is not a Dependency-Track instance: '$versionUrl' reports the application " +
                    "'${application.orEmpty()}'."
            )
        }

        return SbomServer(SbomSourceType.DEPENDENCY_TRACK, apiUrl, about.string("version"))
    }

    /**
     * Return the base URL of the API of the Dependency-Track instance whose frontend is at [baseUrl]: the API server
     * configured in the frontend, or the frontend itself if it serves the API or has no configuration.
     */
    private fun dependencyTrackApiUrl(baseUrl: String): String {
        val config = runCatching { getJsonObject(URI("$baseUrl/static/config.json")) }.getOrNull()
        val configured = config?.string("API_BASE_URL")?.trim()?.takeUnless { it.isEmpty() }
            ?: return baseUrl

        val apiUrl = URI("$baseUrl/").resolve(configured).toString().trimEnd('/')
        if (!apiUrl.startsWith("http://") && !apiUrl.startsWith("https://")) {
            throw SbomServerIdentificationException(
                "The frontend of the Dependency-Track instance at '$baseUrl' configures an invalid API URL " +
                    "'$configured'."
            )
        }

        return apiUrl
    }

    private fun identifySbomify(baseUrl: String): SbomServer {
        val openApiUrl = URI("$baseUrl/api/v1/openapi.json")
        val info = getJsonObject(openApiUrl)?.get("info") as? JsonObject
        val title = info?.string("title")

        if (title == null || !title.contains("sbomify", ignoreCase = true)) {
            throw SbomServerIdentificationException(
                "'$baseUrl' is not a sbomify instance: '$openApiUrl' does not describe the sbomify API."
            )
        }

        return SbomServer(SbomSourceType.SBOMIFY, baseUrl, info.string("version"))
    }

    /**
     * Return the JSON object at the given [url], or *null* if the server answers with another status than 200 or
     * the content is not a JSON object. Throw an [SbomServerIdentificationException] if the server cannot be reached
     * or is temporarily unavailable.
     */
    private fun getJsonObject(url: URI): JsonObject? {
        var currentUrl = url

        repeat(MAX_REDIRECTS + 1) {
            val request = HttpRequest.newBuilder(currentUrl)
                .timeout(requestTimeout)
                .header("Accept", "application/json")
                .GET()
                .build()

            val (response, retries) = try {
                sender.send(request, HttpResponse.BodyHandlers.ofString())
            } catch (e: IOException) {
                throw SbomServerIdentificationException("Could not reach '$currentUrl': ${e.describe()}", e)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw SbomServerIdentificationException("Interrupted while requesting '$currentUrl'.", e)
            }

            val location = response.headers().firstValue("Location").orElse(null)
            if (response.statusCode() in 300..399 && location != null) {
                val target = currentUrl.resolve(location)
                if (!target.host.equals(currentUrl.host, ignoreCase = true) ||
                    (currentUrl.scheme == "https" && target.scheme != "https")
                ) {
                    throw SbomServerIdentificationException(
                        "Refusing the redirect from '$currentUrl' to '$target' while identifying the server."
                    )
                }

                currentUrl = target
                return@repeat
            }

            if (response.statusCode() in RetryPolicy.RETRYABLE_STATUSES) {
                val afterRetries = if (retries > 0) " after $retries retries" else ""
                throw SbomServerIdentificationException(
                    "Could not identify the server: '$currentUrl' answered with status ${response.statusCode()}" +
                        "$afterRetries. The server is temporarily unavailable or overloaded; try again later."
                )
            }

            if (response.statusCode() != 200) return null

            return runCatching { json.parseToJsonElement(response.body()) as? JsonObject }.getOrNull()
        }

        throw SbomServerIdentificationException("Too many redirects for '$url'.")
    }
}

private fun JsonObject.string(key: String): String? = (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content
