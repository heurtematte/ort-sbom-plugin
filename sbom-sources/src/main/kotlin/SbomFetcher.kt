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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.parser.SbomParser

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(SbomFetcher::class.java)

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
 *   credentials is the API key; it needs the permission VIEW_PORTFOLIO.
 * - For a sbomify component, its latest SBOM or the one with the requested version; for a sbomify product, its
 *   aggregated CycloneDX SBOM. The password of the credentials is the access token; public components and products do
 *   not need one.
 * - For a document, its content, with the credentials as basic authentication.
 *
 * Credentials are only sent to the origin of the source: when a request is redirected to another origin, the
 * redirected request is anonymous.
 */
class SbomFetcher(
    private val credentialsProvider: CredentialsProvider = CredentialsProvider.DEFAULT,
    connectTimeout: Duration = Duration.ofSeconds(DEFAULT_CONNECT_TIMEOUT_SECONDS),
    private val requestTimeout: Duration = Duration.ofMinutes(DEFAULT_REQUEST_TIMEOUT_MINUTES)
) {
    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_SECONDS = 30L
        private const val DEFAULT_REQUEST_TIMEOUT_MINUTES = 10L
        private const val MAX_REDIRECTS = 5

        /** The headers that carry credentials. */
        private val CREDENTIAL_HEADERS = setOf("Authorization", "X-Api-Key")

        private val json = Json { ignoreUnknownKeys = true }
    }

    /** Redirects are followed manually, to drop credentials when leaving the origin of a source. */
    private val client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(connectTimeout)
        .build()

    /**
     * Retrieve the SBOM of the given [source] and store it in a new file in [outputDir]. Throw an [IOException] if it
     * cannot be retrieved or is not an SBOM in a supported format.
     */
    fun fetch(source: SbomSource, outputDir: File): FetchedSbom {
        logger.info("Retrieving the SBOM of {}.", source.description)

        val download = when (source) {
            is SbomSource.DependencyTrackProject -> fetchFromDependencyTrack(source)
            is SbomSource.SbomifyComponent -> fetchSbomifyComponent(source)
            is SbomSource.SbomifyProduct -> fetchSbomifyProduct(source)
            is SbomSource.Document -> URI(source.url).let { url -> Download(get(url, basicAuthHeaders(url), source), null, null) }
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

    private fun fetchFromDependencyTrack(source: SbomSource.DependencyTrackProject): Download {
        val api = URI("${source.baseUrl}/api/v1/")
        val headers = credentialsProvider.credentialsFor(api)?.let { mapOf("X-Api-Key" to String(it.password)) }
        if (headers == null) {
            logger.warn("No credentials are available for {}; accessing its API anonymously.", source.baseUrl)
        }

        val apiHeaders = headers.orEmpty()
        val referenced = getJson(api.resolve("project/${source.uuid}"), apiHeaders, source)
        val name = referenced.string("name")
        val referencedVersion = referenced.string("version")

        val project = when (source.version) {
            null, referencedVersion -> referenced

            SbomSource.LATEST -> getJson(api.resolve("project/latest/${name.orEmpty().pathEncode()}"), apiHeaders, source)

            else -> {
                val query = "name=${name.orEmpty().queryEncode()}&version=${source.version.queryEncode()}"
                getJson(api.resolve("project/lookup?$query"), apiHeaders, source)
            }
        }

        val uuid = project.string("uuid") ?: throw IOException("Unexpected response from Dependency-Track: no UUID.")
        val version = project.string("version")
        logger.info("Exporting the SBOM of Dependency-Track project '{}' version '{}' ({}).", name, version, uuid)

        val export = api.resolve("bom/cyclonedx/project/$uuid?format=json&variant=inventory&download=true")
        val content = get(export, apiHeaders + ("Accept" to "application/vnd.cyclonedx+json"), source)

        return Download(content, name, version)
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

    private fun getJson(url: URI, headers: Map<String, String>, source: SbomSource): JsonObject {
        val content = get(url, headers + ("Accept" to "application/json"), source)
        return runCatching { json.parseToJsonElement(content.decodeToString()) }.getOrNull() as? JsonObject
            ?: throw IOException("Unexpected response from '${url.withoutQuery()}' for ${source.description}.")
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

            val response = try {
                client.send(request, HttpResponse.BodyHandlers.ofByteArray())
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("Interrupted while requesting '${currentUrl.withoutQuery()}'.", e)
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
                    throw response.toException(currentUrl, source, hadCredentials)
                }
            }
        }

        throw IOException("Too many redirects for '${url.withoutQuery()}'.")
    }

    private data class Download(val content: ByteArray, val name: String?, val version: String?)
}

private fun HttpResponse<ByteArray>.toException(url: URI, source: SbomSource, hadCredentials: Boolean): IOException {
    val status = statusCode()
    val hint = when {
        status != 401 && status != 403 -> ""

        hadCredentials -> " Check that the credentials for '${url.host}' are valid and have the required permissions."

        else -> " No credentials are available for '${url.host}': in ORT Server, define an infrastructure service " +
            "for this URL; with the ORT CLI, add the host to the '.netrc' file."
    }

    return IOException("Request to '${url.withoutQuery()}' for ${source.description} failed with status $status.$hint")
}

private fun URI.hasSameOrigin(other: URI): Boolean =
    scheme.equals(other.scheme, ignoreCase = true) && host.equals(other.host, ignoreCase = true) &&
        effectivePort() == other.effectivePort()

private fun URI.effectivePort(): Int =
    port.takeIf { it != -1 } ?: if (scheme.equals("https", ignoreCase = true)) 443 else 80

/** Return this URL without query, which may contain signatures for pre-signed downloads, for messages. */
private fun URI.withoutQuery(): String = toString().substringBefore('?')

private fun JsonObject.string(key: String): String? = (get(key) as? JsonPrimitive)?.contentOrNull

private fun String.queryEncode(): String = URLEncoder.encode(this, Charsets.UTF_8)

private fun String.pathEncode(): String = queryEncode().replace("+", "%20")
