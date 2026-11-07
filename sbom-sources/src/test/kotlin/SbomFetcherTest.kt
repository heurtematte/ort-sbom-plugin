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
import org.eclipse.apoapsis.sbom.sources.DependencyTrackResponses.dependencyTrackProject

private const val UUID_1 = "11111111-1111-1111-1111-111111111111"
private const val UUID_2 = "22222222-2222-2222-2222-222222222222"
private const val UUID_3 = "33333333-3333-3333-3333-333333333333"

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

        "explain a missing API key" {
            server.respond("/api/v1/project/$UUID_2-0", status = 401)
            val source = SbomSource.DependencyTrackProject(server.baseUrl, "$UUID_2-0")

            val e = shouldThrow<IOException> { SbomFetcher(CredentialsProvider.NONE).fetch(source, tempdir()) }

            e.message should contain("failed with status 401")
            e.message should contain("define an infrastructure service")
        }

        "explain an API key without permission" {
            server.respond("/api/v1/project/$UUID_2-1", status = 403)
            val source = SbomSource.DependencyTrackProject(server.baseUrl, "$UUID_2-1")

            val e = shouldThrow<IOException> { SbomFetcher(credentials()).fetch(source, tempdir()) }

            e.message should contain("failed with status 403")
            e.message should contain("Check that the credentials")
        }

        "report a version that does not exist" {
            val source = SbomSource.parse("${server.baseUrl}/projects/$UUID_1", version = "9.9.9")

            val e = shouldThrow<IOException> { SbomFetcher(credentials()).fetch(source, tempdir()) }

            e.message should contain("/api/v1/project/lookup' for Dependency-Track project $UUID_1")
            e.message should contain("(version '9.9.9') failed with status 404")
        }
    }

    "Fetching from sbomify" should {
        val cyclonedx = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_7_SBOMIFY)
        val spdx = SbomFixtures.bytes(SbomFixtures.SPDX_3_0_SBOMIFY)

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
})

private fun URI.isOn(server: MockSbomServer): Boolean = toString().startsWith("${server.baseUrl}/")

private fun ByteArray.sha256(): String =
    MessageDigest.getInstance("SHA-256").digest(this).joinToString("") { "%02x".format(it) }
