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

import com.sun.net.httpserver.HttpServer

import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/** A request received by a [MockSbomServer]. */
data class RecordedRequest(
    /** The path and the query of the request. */
    val pathAndQuery: String,

    /** The headers of the request, with lower-case names. */
    val headers: Map<String, String>
)

/**
 * A local HTTP server for tests that simulates SBOM sources, such as the APIs of Dependency-Track and sbomify. Responses
 * are registered per path and query with [respond]; unknown paths result in status 404.
 */
class MockSbomServer : AutoCloseable {
    private class Response(val status: Int, val body: ByteArray, val headers: Map<String, String>)

    private val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
    private val responses = ConcurrentHashMap<String, Response>()

    /** The requests received so far. */
    val requests = CopyOnWriteArrayList<RecordedRequest>()

    /** The base URL of this server, without a trailing slash. */
    val baseUrl: String get() = "http://127.0.0.1:${server.address.port}"

    init {
        server.createContext("/") { exchange ->
            exchange.use {
                val pathAndQuery = exchange.requestURI.rawPath +
                    exchange.requestURI.rawQuery?.let { "?$it" }.orEmpty()
                val headers = exchange.requestHeaders.entries.associate { (name, values) ->
                    name.lowercase() to values.joinToString(",")
                }

                requests += RecordedRequest(pathAndQuery, headers)

                val response = responses[pathAndQuery] ?: Response(404, "Not found".toByteArray(), emptyMap())
                response.headers.forEach { (name, value) -> exchange.responseHeaders.add(name, value) }

                if (response.body.isEmpty()) {
                    exchange.sendResponseHeaders(response.status, -1)
                } else {
                    exchange.sendResponseHeaders(response.status, response.body.size.toLong())
                    exchange.responseBody.write(response.body)
                }
            }
        }

        server.start()
    }

    /** Answer requests to the given [pathAndQuery] with the given [status], [body], and [headers]. */
    fun respond(
        pathAndQuery: String,
        body: ByteArray = ByteArray(0),
        status: Int = 200,
        headers: Map<String, String> = emptyMap()
    ) {
        responses[pathAndQuery] = Response(status, body, headers)
    }

    /** Answer requests to the given [pathAndQuery] with the given JSON [body]. */
    fun respondJson(pathAndQuery: String, body: String) =
        respond(pathAndQuery, body.toByteArray(), headers = mapOf("Content-Type" to "application/json"))

    /** Answer requests to the given [pathAndQuery] with a redirect to the given [location]. */
    fun redirect(pathAndQuery: String, location: String) =
        respond(pathAndQuery, status = 302, headers = mapOf("Location" to location))

    /** Return the requests received for the given [pathAndQuery]. */
    fun requestsTo(pathAndQuery: String): List<RecordedRequest> = requests.filter { it.pathAndQuery == pathAndQuery }

    override fun close() = server.stop(0)
}

/** Answers of a Dependency-Track instance, registered on a [MockSbomServer]. */
object DependencyTrackResponses {
    /**
     * Identify this server as a Dependency-Track instance with the given [version], whose frontend configures the
     * given [apiBaseUrl] as the API server ("" for the frontend itself).
     */
    fun MockSbomServer.dependencyTrackInstance(version: String = "4.14.5", apiBaseUrl: String = "") {
        respondJson("/static/config.json", """{"API_BASE_URL":"$apiBaseUrl","OIDC_CLIENT_ID":null}""")
        respondJson("/api/version", """{"application":"Dependency-Track","version":"$version"}""")
    }

    /**
     * Register a project with the given [uuid], [name], and [version] whose export is the given [sbom], on a server
     * identified as a Dependency-Track instance.
     */
    fun MockSbomServer.dependencyTrackProject(uuid: String, name: String, version: String, sbom: ByteArray) {
        dependencyTrackInstance()
        val project = """{"uuid":"$uuid","name":"$name","version":"$version","isLatest":false}"""
        respondJson("/api/v1/project/$uuid", project)
        respondJson(
            "/api/v1/project/lookup?name=${name.replace(" ", "+")}&version=${version.replace(" ", "+")}",
            project
        )
        respond("/api/v1/bom/cyclonedx/project/$uuid?format=json&variant=inventory&download=true", sbom)
    }
}

object SbomifyResponses {
    /** Identify this server as a sbomify instance with the given [version]. */
    fun MockSbomServer.sbomifyInstance(version: String = "26.11.0") {
        respondJson("/api/v1/openapi.json", """{"openapi":"3.1.0","info":{"title":"sbomify API","version":"$version"}}""")
    }
}
