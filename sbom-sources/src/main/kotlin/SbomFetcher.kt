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

import java.io.File
import java.io.IOException
import java.net.Authenticator
import java.net.PasswordAuthentication
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull

import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.parser.SbomParser

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(SbomFetcher::class.java)

/** The permission that the team of a Dependency-Track API key needs for all requests of [SbomFetcher]. */
private const val DEPENDENCY_TRACK_PERMISSION = "VIEW_PORTFOLIO"

/** Provides the credentials to access a URL, if there are any. */
fun interface CredentialsProvider {
    /** Return the credentials for the given [url], or *null* to access it anonymously. */
    fun credentialsFor(url: URI): PasswordAuthentication?

    companion object {
        /**
         * Obtain credentials from the default [Authenticator] of the JVM. In ORT, this authenticator reads the `.netrc`
         * file; in ORT Server, it provides the credentials of the infrastructure service matching the URL.
         */
        val DEFAULT = CredentialsProvider { url ->
            val port = url.port.takeIf { it != -1 } ?: if (url.scheme.equals("https", ignoreCase = true)) 443 else 80

            Authenticator.requestPasswordAuthentication(
                url.host,
                null,
                port,
                url.scheme,
                "SBOM source",
                url.scheme,
                url.toURL(),
                Authenticator.RequestorType.SERVER
            )
        }

        /** Never provide credentials. */
        val NONE = CredentialsProvider { null }
    }
}

/** An SBOM retrieved from a [source] and stored in a [file]. */
data class FetchedSbom(
    /** The source the SBOM was retrieved from. */
    val source: SbomSource,

    /** The file the SBOM was stored in, whose extension matches the [format]. */
    val file: File,

    /** The format of the SBOM. */
    val format: SbomFormat,

    /** The name of the project or component at the source, if the source has one. */
    val name: String?,

    /** The version of the project or component at the source, if the source has one. */
    val version: String?,

    /** The SHA-256 checksum of the SBOM. */
    val sha256: String
)

/**
 * Retrieve SBOMs from [SbomSource]s, with credentials provided by [credentialsProvider]:
 *
 * - For a Dependency-Track project, the inventory exported by Dependency-Track as CycloneDX JSON. The password of the
 *   credentials is the API key; its team needs the permission VIEW_PORTFOLIO and, if portfolio access control is
 *   enabled, access to the projects. The latest version of a project is the one flagged as latest, or, if there is
 *   none, the active version whose SBOM was imported last.
 * - For a sbomify component, its latest SBOM or the one with the requested version; for a sbomify product, its
 *   aggregated CycloneDX SBOM. The password of the credentials is the access token; public components and products do
 *   not need one.
 * - For a document, its content, with the credentials as basic authentication.
 *
 * Credentials are only sent to the origin of the source: when a request is redirected to another origin, the
 * redirected request is anonymous.
 *
 * Unless [identifyServers] is disabled, the server of a Dependency-Track or sbomify source is first identified with
 * [SbomServerIdentifier], without credentials, and the retrieval fails at once if it is not of the expected type. The
 * identification is done once per server and fetcher. Disable it if the servers were already identified, for instance
 * when the source was registered, and give the identified API URL of Dependency-Track sources in the source.
 *
 * Requests are retried according to [retryPolicy] if a server is temporarily unavailable, for instance during a
 * restart, including the requests to identify servers.
 */
class SbomFetcher(
    private val credentialsProvider: CredentialsProvider = CredentialsProvider.DEFAULT,
    connectTimeout: Duration = Duration.ofSeconds(DEFAULT_CONNECT_TIMEOUT_SECONDS),
    private val requestTimeout: Duration = Duration.ofMinutes(DEFAULT_REQUEST_TIMEOUT_MINUTES),
    private val identifyServers: Boolean = true,
    retryPolicy: RetryPolicy = RetryPolicy()
) {
    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_SECONDS = 30L
        private const val DEFAULT_REQUEST_TIMEOUT_MINUTES = 10L
        private const val MAX_REDIRECTS = 5
        private const val HTTP_NOT_FOUND = 404

        /** The page size and the maximum number of pages when listing the versions of a Dependency-Track project. */
        private const val PAGE_SIZE = 100
        private const val MAX_PAGES = 100

        /** The headers that carry credentials. */
        private val CREDENTIAL_HEADERS = setOf("Authorization", "X-Api-Key")

        private val json = Json { ignoreUnknownKeys = true }
    }

    /** Redirects are followed manually, to drop credentials when leaving the origin of a source. */
    private val sender = RetryingSender(
        HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(connectTimeout)
            .build(),
        retryPolicy
    )

    private val identifier = SbomServerIdentifier(connectTimeout, retryPolicy = retryPolicy)

    /** The servers identified so far, by their type and base URL. */
    private val identifiedServers = ConcurrentHashMap<String, SbomServer>()

    /**
     * Retrieve the SBOM of the given [source] and store it in a new file in [outputDir]. Throw an [IOException] if it
     * cannot be retrieved or is not an SBOM in a supported format.
     */
    fun fetch(source: SbomSource, outputDir: File): FetchedSbom {
        logger.info("Retrieving the SBOM of {}.", source.description)

        val download = when (val resolved = resolveServer(source)) {
            is SbomSource.DependencyTrackProject -> fetchFromDependencyTrack(resolved)
            is SbomSource.SbomifyComponent -> fetchSbomifyComponent(resolved)
            is SbomSource.SbomifyProduct -> fetchSbomifyProduct(resolved)
            is SbomSource.Document -> URI(resolved.url).let { url ->
                Download(get(url, basicAuthHeaders(url), resolved), name = null, version = null)
            }
        }

        val format = SbomParser.detectFormat(download.content)
            ?: throw IOException("The document retrieved from ${source.description} is not an SBOM in a supported format.")

        outputDir.mkdirs()
        val file = File.createTempFile("sbom-", ".${format.fileExtension}", outputDir)
        file.writeBytes(download.content)

        val sha256 = MessageDigest.getInstance("SHA-256").digest(download.content).joinToString("") { "%02x".format(it) }

        logger.info(
            "Retrieved a {} SBOM of {} bytes from {} (sha256:{}).",
            format.displayName,
            download.content.size,
            source.description,
            sha256
        )

        return FetchedSbom(source, file, format, download.name, download.version, sha256)
    }

    /**
     * Return the name of the project, component, or product of the given [source], without retrieving its SBOM, or
     * *null* for a document. Throw an [IOException] if it cannot be retrieved.
     */
    fun fetchName(source: SbomSource): String? =
        when (val resolved = resolveServer(source)) {
            is SbomSource.DependencyTrackProject -> {
                val api = URI("${resolved.apiBaseUrl}/api/v1/")
                val headers = dependencyTrackHeaders(api, resolved)
                getJson(api.resolve("project/${resolved.uuid}"), headers, resolved).string("name")
            }

            is SbomSource.SbomifyComponent -> {
                val api = URI("${resolved.baseUrl}/api/v1/")
                getJson(api.resolve("components/${resolved.id}"), bearerHeaders(api), resolved).string("name")
            }

            is SbomSource.SbomifyProduct -> {
                val api = URI("${resolved.baseUrl}/api/v1/")
                getJson(api.resolve("products/${resolved.id}"), bearerHeaders(api), resolved).string("name")
            }

            is SbomSource.Document -> null
        }

    /**
     * Identify the server of the given [source] if [identifyServers] is enabled, and return the source with the API URL
     * of the server. Throw an [SbomServerIdentificationException] if the server is not of the type of the source.
     */
    private fun resolveServer(source: SbomSource): SbomSource {
        if (!identifyServers || source is SbomSource.Document) return source

        val baseUrl = when (source) {
            is SbomSource.DependencyTrackProject -> source.baseUrl
            is SbomSource.SbomifyComponent -> source.baseUrl
            is SbomSource.SbomifyProduct -> source.baseUrl
            is SbomSource.Document -> source.url
        }

        val server = identifiedServers.getOrPut("${source::class.simpleName} $baseUrl") {
            identifier.identify(source).also { server ->
                logger.info("Identified {} {} at {}.", server.type.id, server.version.orEmpty(), baseUrl)
            }
        }

        return if (source is SbomSource.DependencyTrackProject && source.apiUrl == null) {
            source.copy(apiUrl = server.apiUrl?.takeUnless { it == source.baseUrl })
        } else {
            source
        }
    }

    /**
     * Return the headers with the API key for the Dependency-Track [api] of the given [source]. Throw an [IOException]
     * if no API key is available, as Dependency-Track does not allow anonymous access to projects.
     */
    private fun dependencyTrackHeaders(api: URI, source: SbomSource.DependencyTrackProject): Map<String, String> {
        val credentials = credentialsProvider.credentialsFor(api)
            ?: credentialsProvider.credentialsFor(URI("${source.baseUrl}/"))
            ?: throw IOException(
                "No credentials are available for '${api.host}', but Dependency-Track requires an API key to access " +
                    "${source.description}: in ORT Server, define an infrastructure service for this URL whose " +
                    "password is an API key of a team with the permission '$DEPENDENCY_TRACK_PERMISSION'; with the " +
                    "ORT CLI, add the host to the '.netrc' file."
            )

        return mapOf("X-Api-Key" to String(credentials.password))
    }

    private fun fetchFromDependencyTrack(source: SbomSource.DependencyTrackProject): Download {
        val api = URI("${source.apiBaseUrl}/api/v1/")
        val apiHeaders = dependencyTrackHeaders(api, source)
        val referenced = getJson(api.resolve("project/${source.uuid}"), apiHeaders, source)
        val name = referenced.string("name")
        val referencedVersion = referenced.string("version")

        val project = when (source.version) {
            null, referencedVersion -> referenced

            SbomSource.LATEST -> latestDependencyTrackVersion(api, apiHeaders, source, name.orEmpty())

            else -> {
                val query = "name=${name.orEmpty().queryEncode()}&version=${source.version.queryEncode()}"
                try {
                    getJson(api.resolve("project/lookup?$query"), apiHeaders, source)
                } catch (e: HttpStatusException) {
                    if (e.status != HTTP_NOT_FOUND) throw e

                    throw IOException(
                        "The Dependency-Track project '$name' has no version '${source.version}'. Use one of its " +
                            "versions, '${SbomSource.LATEST}', or no version for the version of the project URL.",
                        e
                    )
                }
            }
        }

        val uuid = project.string("uuid") ?: throw IOException("Unexpected response from Dependency-Track: no UUID.")
        val version = project.string("version")
        logger.info("Exporting the SBOM of Dependency-Track project '{}' version '{}' ({}).", name, version, uuid)

        val export = api.resolve("bom/cyclonedx/project/$uuid?format=json&variant=inventory&download=true")
        val content = get(export, apiHeaders + ("Accept" to "application/vnd.cyclonedx+json"), source)

        return Download(content, name, version)
    }

    /**
     * Return the latest version of the Dependency-Track project with the given [name]: the version flagged as the
     * latest version, or, if no version is flagged or the instance does not support the flag (before
     * Dependency-Track 4.12), the active version whose SBOM was imported last.
     */
    private fun latestDependencyTrackVersion(
        api: URI,
        headers: Map<String, String>,
        source: SbomSource,
        name: String
    ): JsonObject {
        try {
            return getJson(api.resolve("project/latest/${name.pathEncode()}"), headers, source)
        } catch (e: HttpStatusException) {
            if (e.status != HTTP_NOT_FOUND) throw e
        }

        val latest = dependencyTrackVersions(api, headers, source, name)
            .filter { it.boolean("active") != false }
            .mapNotNull { project -> project.long("lastBomImport")?.let { project to it } }
            .maxByOrNull { (_, lastBomImport) -> lastBomImport }
            ?.first
            ?: throw IOException(
                "No active version of the Dependency-Track project '$name' has an SBOM (${source.description})."
            )

        logger.info(
            "No version of the Dependency-Track project '{}' is flagged as the latest version; using version '{}', " +
                "whose SBOM was imported last.",
            name,
            latest.string("version")
        )

        return latest
    }

    /** Return all versions of the Dependency-Track project with the given [name], excluding inactive versions. */
    private fun dependencyTrackVersions(
        api: URI,
        headers: Map<String, String>,
        source: SbomSource,
        name: String
    ): List<JsonObject> {
        val versions = mutableListOf<JsonObject>()

        for (page in 1..MAX_PAGES) {
            val query = "name=${name.queryEncode()}&excludeInactive=true&pageSize=$PAGE_SIZE&pageNumber=$page"
            val items = getJsonArray(api.resolve("project?$query"), headers, source)
            items.filterIsInstance<JsonObject>().filterTo(versions) { it.string("name") == name }
            if (items.size < PAGE_SIZE) break
        }

        return versions
    }

    private fun fetchSbomifyComponent(source: SbomSource.SbomifyComponent): Download {
        val api = URI("${source.baseUrl}/api/v1/")
        val headers = bearerHeaders(api)

        val version = source.version?.takeUnless { it == SbomSource.LATEST }
        val versionFilter = version?.let { "&version=${it.queryEncode()}" }.orEmpty()
        val sboms = getJson(api.resolve("components/${source.id}/sboms?page=1&page_size=1$versionFilter"), headers, source)
        val sbom = ((sboms["items"] as? JsonArray)?.firstOrNull() as? JsonObject)?.get("sbom") as? JsonObject
            ?: throw IOException(
                "The sbomify component '${source.id}' has no SBOM" + version?.let { " with version '$it'" }.orEmpty() +
                    "."
            )

        val id = sbom.string("id") ?: throw IOException("Unexpected response from sbomify: no SBOM ID.")
        val content = get(api.resolve("sboms/$id/download"), headers, source)

        return Download(content, sbom.string("name"), sbom.string("version"))
    }

    private fun fetchSbomifyProduct(source: SbomSource.SbomifyProduct): Download {
        val api = URI("${source.baseUrl}/api/v1/")
        val content = get(api.resolve("products/${source.id}/download?format=cyclonedx"), bearerHeaders(api), source)

        return Download(content, null, null)
    }

    private fun bearerHeaders(url: URI): Map<String, String> =
        credentialsProvider.credentialsFor(url)?.let { mapOf("Authorization" to "Bearer ${String(it.password)}") }
            .orEmpty()

    private fun basicAuthHeaders(url: URI): Map<String, String> =
        credentialsProvider.credentialsFor(url)?.let {
            val token = Base64.getEncoder().encodeToString("${it.userName}:${String(it.password)}".toByteArray())
            mapOf("Authorization" to "Basic $token")
        }.orEmpty()

    private fun getJson(url: URI, headers: Map<String, String>, source: SbomSource): JsonObject =
        getJsonElement(url, headers, source) as? JsonObject
            ?: throw IOException("Unexpected response from '${url.withoutQuery()}' for ${source.description}.")

    private fun getJsonArray(url: URI, headers: Map<String, String>, source: SbomSource): JsonArray =
        getJsonElement(url, headers, source) as? JsonArray
            ?: throw IOException("Unexpected response from '${url.withoutQuery()}' for ${source.description}.")

    private fun getJsonElement(url: URI, headers: Map<String, String>, source: SbomSource): JsonElement? {
        val content = get(url, headers + ("Accept" to "application/json"), source)
        return runCatching { json.parseToJsonElement(content.decodeToString()) }.getOrNull()
    }

    private fun get(url: URI, headers: Map<String, String>, source: SbomSource): ByteArray {
        var currentUrl = url
        var currentHeaders = headers

        repeat(MAX_REDIRECTS + 1) {
            val request = HttpRequest.newBuilder(currentUrl)
                .timeout(requestTimeout)
                .apply { currentHeaders.forEach { (name, value) -> header(name, value) } }
                .GET()
                .build()

            val (response, retries) = try {
                sender.send(request, HttpResponse.BodyHandlers.ofByteArray())
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("Interrupted while requesting '${currentUrl.withoutQuery()}'.", e)
            } catch (e: IOException) {
                throw IOException(
                    "Request to '${currentUrl.withoutQuery()}' for ${source.description} failed: ${e.describe()}",
                    e
                )
            }

            val location = response.headers().firstValue("Location").orElse(null)
            when {
                response.statusCode() in 200..299 -> return response.body()

                response.statusCode() in 300..399 && location != null -> {
                    val target = currentUrl.resolve(location)
                    if (currentUrl.scheme.equals("https", ignoreCase = true) &&
                        !target.scheme.equals("https", ignoreCase = true)
                    ) {
                        throw IOException("Refusing the redirect from '${currentUrl.withoutQuery()}' to '$target'.")
                    }

                    if (!target.hasSameOrigin(currentUrl)) currentHeaders = currentHeaders - CREDENTIAL_HEADERS
                    currentUrl = target
                }

                else -> {
                    val hadCredentials = currentHeaders.keys.any { it in CREDENTIAL_HEADERS }
                    throw response.toException(currentUrl, source, hadCredentials, retries)
                }
            }
        }

        throw IOException("Too many redirects for '${url.withoutQuery()}'.")
    }

    private data class Download(val content: ByteArray, val name: String?, val version: String?)
}

/** A request that failed with the HTTP [status]. */
private class HttpStatusException(val status: Int, message: String) : IOException(message)

private fun HttpResponse<ByteArray>.toException(
    url: URI,
    source: SbomSource,
    hadCredentials: Boolean,
    retries: Int
): HttpStatusException {
    val status = statusCode()
    val isDependencyTrack = source is SbomSource.DependencyTrackProject
    val afterRetries = if (retries > 0) " after $retries retries" else ""
    val hint = when {
        status in RetryPolicy.RETRYABLE_STATUSES -> " The server is temporarily unavailable or overloaded; try again " +
            "later."

        status != 401 && status != 403 -> ""

        hadCredentials && isDependencyTrack -> " Check that the API key for '${url.host}' is valid and that its team " +
            "has the permission '$DEPENDENCY_TRACK_PERMISSION' and, if portfolio access control is enabled, access to " +
            "the project."

        hadCredentials -> " Check that the credentials for '${url.host}' are valid and have the required permissions."

        else -> " No credentials are available for '${url.host}': in ORT Server, define an infrastructure service " +
            "for this URL; with the ORT CLI, add the host to the '.netrc' file." +
            if (isDependencyTrack) {
                " Use an API key of a team with the permission '$DEPENDENCY_TRACK_PERMISSION'."
            } else {
                ""
            }
    }

    return HttpStatusException(
        status,
        "Request to '${url.withoutQuery()}' for ${source.description} failed with status $status$afterRetries.$hint"
    )
}

private fun URI.hasSameOrigin(other: URI): Boolean =
    scheme.equals(other.scheme, ignoreCase = true) && host.equals(other.host, ignoreCase = true) &&
        effectivePort() == other.effectivePort()

private fun URI.effectivePort(): Int =
    port.takeIf { it != -1 } ?: if (scheme.equals("https", ignoreCase = true)) 443 else 80

private fun JsonObject.string(key: String): String? = (get(key) as? JsonPrimitive)?.contentOrNull

private fun JsonObject.long(key: String): Long? = (get(key) as? JsonPrimitive)?.longOrNull

private fun JsonObject.boolean(key: String): Boolean? = (get(key) as? JsonPrimitive)?.booleanOrNull

private fun String.queryEncode(): String = URLEncoder.encode(this, Charsets.UTF_8)

private fun String.pathEncode(): String = queryEncode().replace("+", "%20")
