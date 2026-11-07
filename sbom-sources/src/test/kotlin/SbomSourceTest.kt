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
import io.kotest.matchers.collections.containExactly
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.contain

private const val UUID = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"

class SbomSourceTest : WordSpec({
    "SbomSource.parse()" should {
        "recognize the URL of a Dependency-Track project page" {
            SbomSource.parse("https://sbom.eclipse.org/projects/$UUID") shouldBe
                SbomSource.DependencyTrackProject("https://sbom.eclipse.org", UUID)
        }

        "recognize Dependency-Track behind a context path, with a trailing slash, a query, or a fragment" {
            SbomSource.parse("https://example.org/dtrack/projects/$UUID/?tab=components#x") shouldBe
                SbomSource.DependencyTrackProject("https://example.org/dtrack", UUID)
        }

        "keep the version of a Dependency-Track project" {
            SbomSource.parse("https://sbom.eclipse.org/projects/$UUID", version = " 1.2.3 ") shouldBe
                SbomSource.DependencyTrackProject("https://sbom.eclipse.org", UUID, "1.2.3")
        }

        "recognize the URLs of sbomify component and product pages" {
            SbomSource.parse("https://app.sbomify.com/component/AbC_12-x/") shouldBe
                SbomSource.SbomifyComponent("https://app.sbomify.com", "AbC_12-x")
            SbomSource.parse("https://app.sbomify.com/public/component/AbC/", version = "2.0") shouldBe
                SbomSource.SbomifyComponent("https://app.sbomify.com", "AbC", "2.0")
            SbomSource.parse("https://app.sbomify.com/product/eP_4dk8ixV/") shouldBe
                SbomSource.SbomifyProduct("https://app.sbomify.com", "eP_4dk8ixV")
            SbomSource.parse("https://app.sbomify.com/public/product/eP_4dk8ixV", version = "latest") shouldBe
                SbomSource.SbomifyProduct("https://app.sbomify.com", "eP_4dk8ixV")
        }

        "treat other URLs as documents" {
            val url = "https://github.com/org/repo/releases/download/v1.0/bom.cdx.json"
            SbomSource.parse(url) shouldBe SbomSource.Document(url)
        }

        "use an explicit type" {
            val url = "https://example.org/component/sbom/"
            SbomSource.parse(url, SbomSourceType.DOCUMENT) shouldBe SbomSource.Document(url)
        }

        "reject a URL that does not match an explicit type" {
            val e = shouldThrow<IllegalArgumentException> {
                SbomSource.parse("https://example.org/bom.json", SbomSourceType.forId("Dependency-Track"))
            }

            e.message should contain("not the URL of a Dependency-Track project page")
        }

        "reject versions where they cannot be selected" {
            shouldThrow<IllegalArgumentException> {
                SbomSource.parse("https://example.org/bom.json", version = "1.0")
            }.message should contain("only be selected for Dependency-Track projects and sbomify components")

            shouldThrow<IllegalArgumentException> {
                SbomSource.parse("https://app.sbomify.com/product/abc/", version = "1.0")
            }.message should contain("sbomify products are retrieved in their latest state")
        }

        "reject URLs that are not HTTP URLs" {
            listOf("file:///etc/passwd", "ftp://example.org/bom.json", "not a url", "https://").forEach { url ->
                shouldThrow<IllegalArgumentException> { SbomSource.parse(url) }
            }
        }

        "reject unknown types" {
            shouldThrow<IllegalArgumentException> { SbomSourceType.forId("git") }.message should
                contain("'dependency-track', 'sbomify', 'document'")
        }
    }

    "SbomSourceFile.parse()" should {
        "parse entries given as URLs or maps" {
            val sources = SbomSourceFile.parse(
                """
                # Sources of the SBOMs of the product.
                sources:
                  - https://app.sbomify.com/component/abc/
                  - url: https://sbom.eclipse.org/projects/$UUID
                    version: latest
                  - url: https://example.org/component/sbom/
                    type: document
                """.trimIndent()
            )

            sources should containExactly(
                SbomSource.SbomifyComponent("https://app.sbomify.com", "abc"),
                SbomSource.DependencyTrackProject("https://sbom.eclipse.org", UUID, "latest"),
                SbomSource.Document("https://example.org/component/sbom/")
            )
        }

        "accept an empty list of sources" {
            SbomSourceFile.parse("sources:") should beEmpty()
            SbomSourceFile.parse("sources: []") should beEmpty()
        }

        "report the invalid entry" {
            shouldThrow<IllegalArgumentException> {
                SbomSourceFile.parse(
                    """
                    sources:
                      - https://example.org/bom.json
                      - url: https://example.org/bom.json
                        versoin: 1.0
                    """.trimIndent()
                )
            }.message should contain("Invalid source #2: Unknown keys 'versoin'")
        }

        "reject a document that is not a map with sources" {
            listOf("- https://example.org/bom.json", "source: []", "sources: https://example.org", ": [").forEach {
                shouldThrow<IllegalArgumentException> { SbomSourceFile.parse(it) }
            }
        }

        "reject entries without URL" {
            shouldThrow<IllegalArgumentException> {
                SbomSourceFile.parse("sources:\n  - version: 1.0")
            }.message should contain("The key 'url' is missing.")
        }
    }
})
