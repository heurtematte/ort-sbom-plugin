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

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.WordSpec
import io.kotest.engine.spec.tempdir
import io.kotest.matchers.maps.shouldContain
import io.kotest.matchers.maps.shouldNotContainKey
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.contain
import io.kotest.matchers.string.endWith

import java.io.IOException
import java.net.PasswordAuthentication
import java.net.URI
import java.security.MessageDigest
import java.util.Base64

import org.eclipse.apoapsis.sbom.parser.SbomFixtures
import org.eclipse.apoapsis.sbom.parser.SbomFormat
import org.eclipse.apoapsis.sbom.sources.DependencyTrackResponses.dependencyTrackInstance
import org.eclipse.apoapsis.sbom.sources.DependencyTrackResponses.dependencyTrackProject
import org.eclipse.apoapsis.sbom.sources.SbomifyResponses.sbomifyInstance

private const val UUID_1 = "11111111-1111-1111-1111-111111111111"
private const val UUID_2 = "22222222-2222-2222-2222-222222222222"
private const val UUID_3 = "33333333-3333-3333-3333-333333333333"
private const val UUID_4 = "44444444-4444-4444-4444-444444444444"
private const val UUID_5 = "55555555-5555-5555-5555-555555555555"
private const val UUID_6 = "66666666-6666-6666-6666-666666666666"
private const val UUID_7 = "77777777-7777-7777-7777-777777777777"

private const val EXPORT_QUERY = "?format=json&variant=inventory&download=true"

class SbomFetcherTest : WordSpec({
    val server = MockSbomServer()
    val otherServer = MockSbomServer()

    afterSpec {
        server.close()
        otherServer.close()
    }

    beforeEach {
        server.requests.clear()
        otherServer.requests.clear()
    }

    /** Provide the given credentials only for the main server. */
    fun credentials(username: String = "user", password: String = "secret") = CredentialsProvider { url ->
        PasswordAuthentication(username, password.toCharArray()).takeIf { url.isOn(server) }
    }

    "Fetching a Dependency-Track project" should {
        val cyclonedx = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_JSON)
        val otherCyclonedx = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON)

        server.dependencyTrackProject(UUID_1, "vertx-grpcio-common", "5.0.0.CR7", cyclonedx)
        server.dependencyTrackProject(UUID_2, "vertx-grpcio-common", "4.0.0", otherCyclonedx)
        server.dependencyTrackProject(UUID_3, "vertx-grpcio-common", "5.1.0", otherCyclonedx)
        server.respondJson(
            "/api/v1/project/latest/vertx-grpcio-common",
            """{"uuid":"$UUID_3","name":"vertx-grpcio-common","version":"5.1.0","isLatest":true}"""
        )

        "export the referenced project with the API key" {
            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_1")

            val fetched = SbomFetcher(credentials(password = "api-key")).fetch(source, tempdir())

            fetched.file.readBytes() shouldBe cyclonedx
            fetched.file.name should endWith(".cdx.json")
            fetched.format shouldBe SbomFormat.CYCLONEDX_JSON
            fetched.name shouldBe "vertx-grpcio-common"
            fetched.version shouldBe "5.0.0.CR7"
            fetched.sha256 shouldBe cyclonedx.sha256()

            val export = server.requestsTo("/api/v1/bom/cyclonedx/project/$UUID_1$EXPORT_QUERY").single()
            export.headers shouldContain ("x-api-key" to "api-key")
            export.headers shouldNotContainKey "authorization"
        }

        "export another version of the project" {
            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_1", version = "4.0.0")

            val fetched = SbomFetcher(credentials()).fetch(source, tempdir())

            fetched.file.readBytes() shouldBe otherCyclonedx
            fetched.version shouldBe "4.0.0"
            server.requestsTo("/api/v1/project/lookup?name=vertx-grpcio-common&version=4.0.0").size shouldBe 1
        }

        "export the latest version of the project" {
            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_1", version = "latest")

            val fetched = SbomFetcher(credentials()).fetch(source, tempdir())

            fetched.version shouldBe "5.1.0"
            server.requestsTo("/api/v1/bom/cyclonedx/project/$UUID_3$EXPORT_QUERY").size shouldBe 1
        }

        "export the active version imported last if no version is flagged as the latest version" {
            // Dependency-Track answers 404 for project/latest/vertx-core, as no version is flagged.
            server.dependencyTrackProject(UUID_4, "vertx-core", "4.5.0", otherCyclonedx)
            server.dependencyTrackProject(UUID_5, "vertx-core", "5.0.0", cyclonedx)
            server.respondJson(
                "/api/v1/project?name=vertx-core&excludeInactive=true&pageSize=100&pageNumber=1",
                """
                [
                  {"uuid":"$UUID_4","name":"vertx-core","version":"4.5.0","active":true,"lastBomImport":1000},
                  {"uuid":"$UUID_5","name":"vertx-core","version":"5.0.0","active":true,"lastBomImport":3000},
                  {"uuid":"$UUID_6","name":"vertx-core","version":"6.0.0","active":false,"lastBomImport":4000},
                  {"uuid":"$UUID_7","name":"vertx-core","version":"5.1.0","active":true},
                  {"uuid":"$UUID_1","name":"vertx-core-tests","version":"5.2.0","active":true,"lastBomImport":5000}
                ]
                """.trimIndent()
            )

            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_4", version = "latest")

            val fetched = SbomFetcher(credentials()).fetch(source, tempdir())

            fetched.version shouldBe "5.0.0"
            fetched.file.readBytes() shouldBe cyclonedx
            server.requestsTo("/api/v1/project/latest/vertx-core").size shouldBe 1
        }

        "report a project without any version with an SBOM" {
            server.dependencyTrackProject(UUID_6, "vertx-web", "1.0.0", otherCyclonedx)
            server.respondJson(
                "/api/v1/project?name=vertx-web&excludeInactive=true&pageSize=100&pageNumber=1",
                """[{"uuid":"$UUID_6","name":"vertx-web","version":"1.0.0","active":true}]"""
            )

            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_6", version = "latest")

            val e = shouldThrow<IOException> { SbomFetcher(credentials()).fetch(source, tempdir()) }

            e.message should contain("No active version of the Dependency-Track project 'vertx-web' has an SBOM")
        }

        "not hide other errors when looking up the latest version" {
            server.dependencyTrackProject(UUID_7, "vertx-auth", "1.0.0", otherCyclonedx)
            server.respond("/api/v1/project/latest/vertx-auth", status = 403)

            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_7", version = "latest")

            val e = shouldThrow<IOException> { SbomFetcher(credentials()).fetch(source, tempdir()) }

            e.message should contain("/api/v1/project/latest/vertx-auth' for Dependency-Track project")
            e.message should contain("failed with status 403")
        }

        "explain a missing API key" {
            server.respond("/api/v1/project/$UUID_2-0", status = 401)
            val source = SbomSource.DependencyTrackProject(server.baseUrl, "$UUID_2-0")

            val e = shouldThrow<IOException> { SbomFetcher(CredentialsProvider.NONE).fetch(source, tempdir()) }

            e.message should contain("No credentials are available for '127.0.0.1'")
            e.message should contain("define an infrastructure service")
            e.message should contain("permission 'VIEW_PORTFOLIO'")
            server.requestsTo("/api/v1/project/$UUID_2-0").size shouldBe 0
        }

        "explain an API key without permission" {
            server.respond("/api/v1/project/$UUID_2-1", status = 403)
            val source = SbomSource.DependencyTrackProject(server.baseUrl, "$UUID_2-1")

            val e = shouldThrow<IOException> { SbomFetcher(credentials()).fetch(source, tempdir()) }

            e.message should contain("failed with status 403")
            e.message should contain("Check that the API key for '127.0.0.1' is valid")
            e.message should contain("the permission 'VIEW_PORTFOLIO' and, if portfolio access control is enabled")
        }

        "report a version that does not exist" {
            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_1", version = "9.9.9")

            val e = shouldThrow<IOException> { SbomFetcher(credentials()).fetch(source, tempdir()) }

            e.message shouldBe "The Dependency-Track project 'vertx-grpcio-common' has no version '9.9.9'. Use one " +
                "of its versions, 'latest', or no version for the version of the project URL."
        }
    }

    "Fetching from sbomify" should {
        val cyclonedx = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_7_SBOMIFY)
        val spdx = SbomFixtures.bytes(SbomFixtures.SPDX_3_0_SBOMIFY)

        server.sbomifyInstance()
        server.respondJson("/api/v1/components/comp1", """{"id":"comp1","name":"comp"}""")
        server.respondJson(
            "/api/v1/components/comp1/sboms?page=1&page_size=1",
            """{"items":[{"sbom":{"id":"sbom-latest","name":"comp","version":"2.0","format":"cyclonedx"}}]}"""
        )
        server.respondJson(
            "/api/v1/components/comp1/sboms?page=1&page_size=1&version=1.0",
            """{"items":[{"sbom":{"id":"sbom-old","name":"comp","version":"1.0","format":"spdx"}}]}"""
        )
        server.respondJson("/api/v1/components/comp1/sboms?page=1&page_size=1&version=0.1", """{"items":[]}""")
        server.respond("/api/v1/sboms/sbom-latest/download", cyclonedx)
        server.respond("/api/v1/sboms/sbom-old/download", spdx)
        server.respond("/api/v1/products/prod1/download?format=cyclonedx", cyclonedx)

        "download the latest SBOM of a component with the access token" {
            val source = SbomSource.parse("${server.baseUrl}/component/comp1/")

            val fetched = SbomFetcher(credentials(password = "token")).fetch(source, tempdir())

            fetched.file.readBytes() shouldBe cyclonedx
            fetched.name shouldBe "comp"
            fetched.version shouldBe "2.0"
            server.requestsTo("/api/v1/sboms/sbom-latest/download").single().headers shouldContain
                ("authorization" to "Bearer token")
        }

        "download the SBOM of a component with the requested version" {
            val source = SbomSource.parse("${server.baseUrl}/public/component/comp1/", version = "1.0")

            val fetched = SbomFetcher(CredentialsProvider.NONE).fetch(source, tempdir())

            fetched.file.readBytes() shouldBe spdx
            fetched.format shouldBe SbomFormat.SPDX3_JSON_LD
            fetched.version shouldBe "1.0"
            server.requestsTo("/api/v1/sboms/sbom-old/download").single().headers shouldNotContainKey "authorization"
        }

        "report a component without SBOM for the requested version" {
            val source = SbomSource.parse("${server.baseUrl}/component/comp1/", version = "0.1")

            shouldThrow<IOException> { SbomFetcher().fetch(source, tempdir()) }.message shouldBe
                "The sbomify component 'comp1' has no SBOM with version '0.1'."
        }

        "download the SBOM of a product" {
            val source = SbomSource.parse("${server.baseUrl}/product/prod1/")

            val fetched = SbomFetcher(CredentialsProvider.NONE).fetch(source, tempdir())

            fetched.file.readBytes() shouldBe cyclonedx
            fetched.name shouldBe null
        }
    }

    "Fetching a document" should {
        val tagValue = SbomFixtures.bytes(SbomFixtures.SPDX_2_3_TAG_VALUE)
        server.respond("/files/sbom.spdx", tagValue)
        server.respond("/files/readme.txt", "Hello".toByteArray())

        "download it with basic authentication" {
            val source = SbomSource.parse("${server.baseUrl}/files/sbom.spdx")

            val fetched = SbomFetcher(credentials()).fetch(source, tempdir())

            fetched.file.readBytes() shouldBe tagValue
            fetched.file.name should endWith(".spdx")
            val basic = Base64.getEncoder().encodeToString("user:secret".toByteArray())
            server.requestsTo("/files/sbom.spdx").single().headers shouldContain ("authorization" to "Basic $basic")
        }

        "reject a document that is not an SBOM" {
            val source = SbomSource.parse("${server.baseUrl}/files/readme.txt")

            shouldThrow<IOException> { SbomFetcher().fetch(source, tempdir()) }.message should
                contain("is not an SBOM in a supported format")
        }

        "keep the credentials on redirects to the same origin" {
            server.redirect("/files/latest.spdx", "/files/sbom.spdx")
            val source = SbomSource.parse("${server.baseUrl}/files/latest.spdx")

            SbomFetcher(credentials()).fetch(source, tempdir()).file.readBytes() shouldBe tagValue

            server.requestsTo("/files/sbom.spdx").single().headers.keys.contains("authorization") shouldBe true
        }

        "drop the credentials on redirects to another origin" {
            otherServer.respond("/assets/sbom.spdx", tagValue)
            server.redirect("/files/elsewhere.spdx", "${otherServer.baseUrl}/assets/sbom.spdx")
            val source = SbomSource.parse("${server.baseUrl}/files/elsewhere.spdx")

            SbomFetcher(credentials()).fetch(source, tempdir()).file.readBytes() shouldBe tagValue

            server.requestsTo("/files/elsewhere.spdx").single().headers.keys.contains("authorization") shouldBe true
            otherServer.requestsTo("/assets/sbom.spdx").single().headers shouldNotContainKey "authorization"
        }

        "stop after too many redirects" {
            server.redirect("/files/loop", "/files/loop")
            val source = SbomSource.parse("${server.baseUrl}/files/loop")

            shouldThrow<IOException> { SbomFetcher().fetch(source, tempdir()) }.message should
                contain("Too many redirects")
        }
    }

    "Identifying the server" should {
        val cyclonedx = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_JSON)

        "fail before sending credentials to a server that is not Dependency-Track" {
            MockSbomServer().use { notDependencyTrack ->
                notDependencyTrack.respondJson("/api/v1/project/$UUID_5", """{"uuid":"$UUID_5"}""")
                val source = SbomSource.DependencyTrackProject(notDependencyTrack.baseUrl, UUID_5)
                val credentials = CredentialsProvider { PasswordAuthentication("", "secret".toCharArray()) }

                val e = shouldThrow<SbomServerIdentificationException> {
                    SbomFetcher(credentials).fetch(source, tempdir())
                }

                e.message should contain("is not a Dependency-Track instance")
                notDependencyTrack.requests.filter { "x-api-key" in it.headers }.size shouldBe 0
                notDependencyTrack.requestsTo("/api/v1/project/$UUID_5").size shouldBe 0
            }
        }

        "call the API server configured in the frontend" {
            otherServer.dependencyTrackProject(UUID_6, "api-server-project", "1.0.0", cyclonedx)

            MockSbomServer().use { frontend ->
                frontend.dependencyTrackInstance(apiBaseUrl = otherServer.baseUrl)
                val credentials = CredentialsProvider { url ->
                    PasswordAuthentication("", "secret".toCharArray()).takeIf { url.isOn(frontend) }
                }

                val fetched = SbomFetcher(credentials)
                    .fetch(SbomSource.DependencyTrackProject(frontend.baseUrl, UUID_6), tempdir())

                fetched.name shouldBe "api-server-project"
                otherServer.requestsTo("/api/v1/project/$UUID_6").single().headers shouldContain ("x-api-key" to "secret")
                frontend.requestsTo("/api/v1/project/$UUID_6").size shouldBe 0
            }
        }

        "not identify the server if disabled" {
            val source = SbomSource.DependencyTrackProject(server.baseUrl, UUID_1)

            SbomFetcher(credentials(), identifyServers = false).fetch(source, tempdir())

            server.requestsTo("/api/version").size shouldBe 0
            server.requestsTo("/static/config.json").size shouldBe 0
        }

        "identify a server only once" {
            val fetcher = SbomFetcher(credentials())

            fetcher.fetch(SbomSource.DependencyTrackProject(server.baseUrl, UUID_1), tempdir())
            fetcher.fetch(SbomSource.DependencyTrackProject(server.baseUrl, UUID_2), tempdir())

            server.requestsTo("/api/version").size shouldBe 1
        }
    }

    "Fetching the name of a source" should {
        "return the name of a Dependency-Track project without exporting its SBOM" {
            val source = SbomSource.DependencyTrackProject(server.baseUrl, UUID_1)

            SbomFetcher(credentials()).fetchName(source) shouldBe "vertx-grpcio-common"

            server.requestsTo("/api/v1/bom/cyclonedx/project/$UUID_1$EXPORT_QUERY").size shouldBe 0
        }

        "return the name of a sbomify component" {
            SbomFetcher(CredentialsProvider.NONE).fetchName(SbomSource.parse("${server.baseUrl}/component/comp1/")) shouldBe
                "comp"
        }

        "return no name for a document" {
            SbomFetcher(CredentialsProvider.NONE).fetchName(SbomSource.Document("${server.baseUrl}/sbom.json")) shouldBe
                null
        }
    }
})

private fun URI.isOn(server: MockSbomServer): Boolean = toString().startsWith("${server.baseUrl}/")

private fun ByteArray.sha256(): String =
    MessageDigest.getInstance("SHA-256").digest(this).joinToString("") { "%02x".format(it) }
