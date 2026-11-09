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
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.contain

import org.eclipse.apoapsis.sbom.sources.DependencyTrackResponses.dependencyTrackInstance
import org.eclipse.apoapsis.sbom.sources.SbomifyResponses.sbomifyInstance

private const val UUID = "11111111-1111-1111-1111-111111111111"

class SbomServerIdentifierTest : WordSpec({
    val identifier = SbomServerIdentifier()

    "identify" should {
        "identify a Dependency-Track instance that serves its API" {
            MockSbomServer().use { server ->
                server.dependencyTrackInstance(version = "4.14.5")

                identifier.identify(SbomSource.DependencyTrackProject(server.baseUrl, UUID)) shouldBe
                    SbomServer(SbomSourceType.DEPENDENCY_TRACK, server.baseUrl, "4.14.5")
            }
        }

        "identify a Dependency-Track instance without frontend configuration" {
            MockSbomServer().use { server ->
                server.respondJson("/api/version", """{"application":"Dependency-Track","version":"5.2.1"}""")

                identifier.identify(SbomSource.DependencyTrackProject(server.baseUrl, UUID)) shouldBe
                    SbomServer(SbomSourceType.DEPENDENCY_TRACK, server.baseUrl, "5.2.1")
            }
        }

        "use the API server configured in the frontend" {
            MockSbomServer().use { frontend ->
                MockSbomServer().use { api ->
                    frontend.respondJson("/static/config.json", """{"API_BASE_URL":"${api.baseUrl}/"}""")
                    api.respondJson("/api/version", """{"application":"Dependency-Track","version":"4.13.0"}""")

                    identifier.identify(SbomSource.DependencyTrackProject(frontend.baseUrl, UUID)) shouldBe
                        SbomServer(SbomSourceType.DEPENDENCY_TRACK, api.baseUrl, "4.13.0")
                }
            }
        }

        "reject a server without the version endpoint of Dependency-Track" {
            MockSbomServer().use { server ->
                val e = shouldThrow<SbomServerIdentificationException> {
                    identifier.identify(SbomSource.DependencyTrackProject(server.baseUrl, UUID))
                }

                e.message shouldBe "'${server.baseUrl}' is not a Dependency-Track instance: " +
                    "'${server.baseUrl}/api/version' did not return the version of Dependency-Track."
            }
        }

        "reject another application" {
            MockSbomServer().use { server ->
                server.respondJson("/api/version", """{"application":"Other","version":"1.0"}""")

                val e = shouldThrow<SbomServerIdentificationException> {
                    identifier.identify(SbomSource.DependencyTrackProject(server.baseUrl, UUID))
                }

                e.message should contain("reports the application 'Other'")
            }
        }

        "refuse a redirect to another host" {
            MockSbomServer().use { server ->
                server.redirect("/api/version", "http://localhost:1/api/version")

                val e = shouldThrow<SbomServerIdentificationException> {
                    identifier.identify(SbomSource.DependencyTrackProject(server.baseUrl, UUID))
                }

                e.message should contain("Refusing the redirect")
            }
        }

        "report a server that cannot be reached" {
            val e = shouldThrow<SbomServerIdentificationException> {
                identifier.identify(SbomSource.DependencyTrackProject("http://127.0.0.1:1", UUID))
            }

            e.message should contain("Could not reach 'http://127.0.0.1:1/")
        }

        "identify a sbomify instance" {
            MockSbomServer().use { server ->
                server.sbomifyInstance(version = "26.11.0")

                identifier.identify(SbomSource.parse("${server.baseUrl}/public/product/prod1/")) shouldBe
                    SbomServer(SbomSourceType.SBOMIFY, server.baseUrl, "26.11.0")
            }
        }

        "reject a server that is not sbomify" {
            MockSbomServer().use { server ->
                server.respondJson("/api/v1/openapi.json", """{"info":{"title":"Other API","version":"1"}}""")

                val e = shouldThrow<SbomServerIdentificationException> {
                    identifier.identify(SbomSource.parse("${server.baseUrl}/component/comp1/"))
                }

                e.message should contain("is not a sbomify instance")
            }
        }

        "not request anything for a document" {
            MockSbomServer().use { server ->
                identifier.identify(SbomSource.Document("${server.baseUrl}/sbom.json")) shouldBe
                    SbomServer(SbomSourceType.DOCUMENT, apiUrl = null, version = null)

                server.requests.size shouldBe 0
            }
        }
    }
})
