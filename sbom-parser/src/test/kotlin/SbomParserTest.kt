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

package org.eclipse.apoapsis.sbom.parser

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.collections.containExactly
import io.kotest.matchers.collections.containExactlyInAnyOrder
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.maps.haveSize
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.string.contain

class SbomParserTest : WordSpec({
    "detectFormat" should {
        SbomFixtures.ALL.forEach { (path, expected) ->
            "detect ${expected.first} for '$path'" {
                SbomParser.detectFormat(SbomFixtures.bytes(path)) shouldBe expected.first
            }
        }

        "return null for documents that are not SBOMs" {
            SbomParser.detectFormat("""{"name": "package.json"}""".toByteArray()) should beNull()
            SbomParser.detectFormat("<project/>".toByteArray()) should beNull()
            SbomParser.detectFormat("plain text".toByteArray()) should beNull()
        }
    }

    "parse" should {
        SbomFixtures.ALL.forEach { (path, expected) ->
            "parse '$path' as ${expected.first.displayName} ${expected.second}" {
                val sbom = SbomParser.parse(SbomFixtures.bytes(path))

                sbom.format shouldBe expected.first
                sbom.specVersion shouldBe expected.second
                sbom.warnings.filter { "has not been tested" in it } should beEmpty()
            }
        }

        "parse SPDX documents encoded in UTF-16" {
            val json = SbomParser.parse(SbomFixtures.bytes(SbomFixtures.SPDX_2_2_JSON_UTF16))
            val tagValue = SbomParser.parse(SbomFixtures.bytes(SbomFixtures.SPDX_2_2_TAG_VALUE_UTF16))

            json.name shouldBe "SPDX-Tools-v2.0"
            json.components.values.map { it.name } should containExactlyInAnyOrder(
                tagValue.components.values.map { it.name }
            )
            json.components.values.map { it.name } shouldContain "glibc"
        }

        "parse SPDX 2 documents in XML format" {
            val sbom = SbomParser.parse(SbomFixtures.bytes(SbomFixtures.SPDX_2_3_XML))

            sbom.name shouldBe "SPDX-Tools-v2.0"
            sbom.roots shouldNot beEmpty()
            sbom.components.values.mapNotNull { it.purl } shouldContain "pkg:maven/org.apache.jena/apache-jena@3.12.0"
            sbom.relationships.values.flatten() shouldNot beEmpty()
        }

        "accept CycloneDX documents with invalid metadata and report it" {
            val sbom = SbomParser.parse(SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_7_INVALID_METADATA))

            sbom.components.isNotEmpty() shouldBe true
            sbom.warnings.single() should contain("timestamp")
        }

        "parse SPDX 3 documents that consist of a single element" {
            val sbom = SbomParser.parse(SbomFixtures.bytes(SbomFixtures.SPDX_3_0_SINGLE_ELEMENT))

            sbom.components.values.single().let {
                it.name shouldBe "packageName"
                it.version shouldBe "12.2"
            }
        }

        "treat a 'describes' relationship of an SPDX 3 package as composition" {
            val sbom = SbomParser.parse(SbomFixtures.bytes(SbomFixtures.SPDX_3_0_SBOMIFY))

            val root = sbom.components.getValue(sbom.roots.single())
            root.name shouldBe "sbomify - latest"
            sbom.dependenciesOf(root.ref).size shouldBe 6
            sbom.components.size shouldBe 7
        }

        "warn about specification versions that have not been tested" {
            val content = SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_2_JSON).decodeToString()
                .replace("\"specVersion\": \"1.2\"", "\"specVersion\": \"1.9\"")

            val sbom = SbomParser.parse(content.toByteArray())

            sbom.specVersion shouldBe "1.9"
            sbom.warnings.single() should contain("'1.9' has not been tested")
        }

        "extract the root component, components, and dependencies of a CycloneDX 1.4 SBOM" {
            val sbom = SbomParser.parse(SbomFixtures.bytes("cyclonedx/angus-imap-2.0.3-v1.4.cdx.json"))

            sbom.format shouldBe SbomFormat.CYCLONEDX_JSON
            sbom.specVersion shouldBe "1.4"
            sbom.roots should containExactly(ANGUS_IMAP)
            sbom.components should haveSize(5)
            sbom.defaultScope shouldBe "required"

            with(sbom.components.getValue(ANGUS_IMAP)) {
                group shouldBe "org.eclipse.angus"
                name shouldBe "imap"
                version shouldBe "2.0.3"
                declaredLicenses should containExactlyInAnyOrder(
                    "EPL-2.0", "GPL-2.0-with-classpath-exception", "BSD-3-Clause"
                )
            }

            with(sbom.components.getValue(JAKARTA_MAIL_API)) {
                purl shouldBe JAKARTA_MAIL_API
                scope shouldBe "required"
                vcsUrl shouldBe "https://github.com/jakartaee/mail-api"
                hashes.map { it.algorithm } should containExactlyInAnyOrder(
                    "MD5", "SHA1", "SHA256", "SHA512", "SHA384", "SHA3384", "SHA3256", "SHA3512"
                )
            }

            sbom.dependenciesOf(ANGUS_IMAP).map { it.target } should containExactly(JAKARTA_MAIL_API, ANGUS_CORE)
        }

        "yield the same content for the JSON and XML serialization of a CycloneDX SBOM" {
            listOf("angus-imap-2.0.3-v1.4", "vertx-grpcio-common-5.0.0.CR7-v1.6").forEach { name ->
                val json = SbomParser.parse(SbomFixtures.bytes("cyclonedx/$name.cdx.json"))
                val xml = SbomParser.parse(SbomFixtures.bytes("cyclonedx/$name.cdx.xml"))

                xml.format shouldBe SbomFormat.CYCLONEDX_XML
                xml.specVersion shouldBe json.specVersion
                xml.roots shouldBe json.roots
                xml.components.values.map { it.copy(description = null) } shouldBe
                    json.components.values.map { it.copy(description = null) }
                xml.relationships shouldBe json.relationships
            }
        }

        "handle a CycloneDX SBOM that only describes its root component" {
            val sbom = SbomParser.parse(SbomFixtures.bytes("cyclonedx/krazo-documentation-4.0.0-v1.4.cdx.json"))

            sbom.roots.single() shouldBe "pkg:maven/org.eclipse.krazo/krazo-documentation@4.0.0?type=pom"
            sbom.components.keys should containExactly(sbom.roots.single())
            sbom.relationships.values.flatten() should beEmpty()
        }

        "handle a flat CycloneDX SBOM with components without purls and without dependencies" {
            val sbom = SbomParser.parse(SbomFixtures.bytes("cyclonedx/temurin-jdk-21.0.13-v1.6.cdx.json"))

            sbom.specVersion shouldBe "1.6"
            sbom.roots shouldBe listOf(sbom.components.keys.first())
            sbom.components.values.drop(1).map { it.name } should containExactly(
                "JDK Component", "JRE Component", "STATIC-LIBS Component", "DEBUGIMAGE Component",
                "TESTIMAGE Component"
            )
            sbom.components.values.drop(1).map { it.purl } should containExactly(null, null, null, null, null)
            sbom.relationships.values.flatten() should beEmpty()
        }

        "extract the packages and relationships of an SPDX 2.3 SBOM" {
            val sbom = SbomParser.parse(SbomFixtures.bytes("spdx/p2repo-sbom-v2.3.spdx.json"))

            sbom.format shouldBe SbomFormat.SPDX_JSON
            sbom.specVersion shouldBe "SPDX-2.3"
            sbom.name shouldBe "com.github.eclipse-cbi/p2repo-sbom"
            sbom.roots should containExactly(P2REPO_ROOT)
            sbom.components should haveSize(21)
            sbom.dependenciesOf(P2REPO_ROOT).size shouldBe 20

            with(sbom.components.getValue(TYCHO_DIRECTOR)) {
                name shouldBe "org.eclipse.tycho:tycho-p2-director-plugin"
                version should beNull()
                purl shouldBe "pkg:maven/org.eclipse.tycho/tycho-p2-director-plugin"
            }
        }

        "yield the same content for all serializations of an SPDX SBOM" {
            val json = SbomParser.parse(SbomFixtures.bytes("spdx/p2repo-sbom-v2.3.spdx.json"))

            listOf(
                "spdx/p2repo-sbom-v2.3.spdx.yaml" to SbomFormat.SPDX_YAML,
                "spdx/p2repo-sbom-v2.3.spdx" to SbomFormat.SPDX_TAG_VALUE,
                "spdx/p2repo-sbom-v3.0.1.spdx3.json" to SbomFormat.SPDX3_JSON_LD
            ).forEach { (path, format) ->
                val sbom = SbomParser.parse(SbomFixtures.bytes(path))

                sbom.format shouldBe format
                sbom.roots.map { it.substringAfterLast('#') } shouldBe json.roots
                sbom.components.values.map { it.copy(ref = it.ref.substringAfterLast('#')) } shouldBe
                    json.components.values.toList()
                sbom.relationships.mapKeys { it.key.substringAfterLast('#') }.mapValues { (_, edges) ->
                    edges.map { it.copy(target = it.target.substringAfterLast('#')) }
                } shouldBe json.relationships
            }
        }

        "keep the scope of SPDX dependency relationships" {
            val sbom = SbomParser.parse(
                """
                SPDXVersion: SPDX-2.3
                DataLicense: CC0-1.0
                SPDXID: SPDXRef-DOCUMENT
                DocumentName: scopes
                DocumentNamespace: https://example.org/scopes
                Creator: Tool: test

                PackageName: app
                SPDXID: SPDXRef-app
                PackageDownloadLocation: git+https://github.com/example/app.git@v1
                PackageLicenseDeclared: Apache-2.0

                PackageName: junit
                SPDXID: SPDXRef-junit
                PackageVersion: 4.13.2
                PackageDownloadLocation: NOASSERTION
                PackageCopyrightText: <text>Copyright
                JUnit authors</text>
                ExternalRef: PACKAGE-MANAGER purl pkg:maven/junit/junit@4.13.2

                Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-app
                Relationship: SPDXRef-junit TEST_DEPENDENCY_OF SPDXRef-app
                """.trimIndent().toByteArray()
            )

            sbom.format shouldBe SbomFormat.SPDX_TAG_VALUE
            sbom.roots should containExactly("SPDXRef-app")
            sbom.dependenciesOf("SPDXRef-app") should containExactly(SbomRelationship("SPDXRef-junit", "test"))
            sbom.components.getValue("SPDXRef-app").vcsUrl shouldBe "git+https://github.com/example/app.git@v1"
            sbom.components.getValue("SPDXRef-junit").copyright shouldBe "Copyright\nJUnit authors"
        }

        "reject documents in unsupported formats" {
            shouldThrow<SbomParseException> {
                SbomParser.parse("""{"name": "package.json"}""".toByteArray())
            }.message should contain("neither a CycloneDX nor an SPDX document")

            shouldThrow<SbomParseException> {
                SbomParser.parse(
                    """<rdf:RDF xmlns:spdx="http://spdx.org/rdf/terms#"></rdf:RDF>""".toByteArray()
                )
            }.message should contain("RDF/XML")

            shouldThrow<SbomParseException> { SbomParser.parse(ByteArray(0)) }
        }

        "reject invalid documents" {
            shouldThrow<SbomParseException> {
                SbomParser.parse("""{"bomFormat": "CycloneDX", "specVersion": """.toByteArray())
            }
        }
    }
})

private const val ANGUS_IMAP = "pkg:maven/org.eclipse.angus/imap@2.0.3?type=jar"
private const val ANGUS_CORE = "pkg:maven/org.eclipse.angus/angus-core@2.0.3?type=jar"
private const val JAKARTA_MAIL_API = "pkg:maven/jakarta.mail/jakarta.mail-api@2.1.3?type=jar"
private const val P2REPO_ROOT = "SPDXRef-github-eclipse-cbi-p2repo-sbom-main-ee4f54"
private const val TYCHO_DIRECTOR = "SPDXRef-maven-org.eclipse.tycho-tycho-p2-director-plugin-88b080"
