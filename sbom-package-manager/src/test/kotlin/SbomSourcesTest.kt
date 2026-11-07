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

package org.eclipse.apoapsis.sbom.packagemanager

import io.kotest.core.spec.style.WordSpec
import io.kotest.engine.spec.tempdir
import io.kotest.matchers.collections.containExactly
import io.kotest.matchers.collections.contain
import io.kotest.matchers.collections.containExactlyInAnyOrder
import io.kotest.matchers.maps.beEmpty as beEmptyMap
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.contain as containString

import java.io.File
import java.net.Authenticator
import java.net.PasswordAuthentication

import kotlin.io.path.createTempDirectory

import org.eclipse.apoapsis.sbom.parser.SbomFixtures
import org.eclipse.apoapsis.sbom.sources.DependencyTrackResponses.dependencyTrackProject
import org.eclipse.apoapsis.sbom.sources.MockSbomServer

import org.ossreviewtoolkit.analyzer.Analyzer
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.OrtResult
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.model.config.PackageManagerConfiguration

private const val UUID = "44444444-4444-4444-4444-444444444444"

class SbomSourcesTest : WordSpec({
    val server = MockSbomServer()

    server.dependencyTrackProject(UUID, "angus-imap", "2.0.3", SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_4_JSON))
    server.respond("/releases/vertx.cdx.xml", SbomFixtures.bytes(SbomFixtures.CYCLONEDX_1_6_XML))
    server.respond("/releases/product.spdx3.json", SbomFixtures.bytes(SbomFixtures.SPDX_3_0_SBOMIFY))

    afterSpec { server.close() }

    afterEach { Authenticator.setDefault(null) }

    "The SBOM package manager" should {
        "analyze the SBOMs of the sources listed in a source file" {
            val dir = tempdir()
            File(dir, "sbom-sources.yml").writeText(
                """
                sources:
                  - ${server.baseUrl}/projects/$UUID
                  - url: ${server.baseUrl}/releases/vertx.cdx.xml
                """.trimIndent()
            )

            val result = analyze(dir)

            result.getAnalyzerIssues(minSeverity = Severity.ERROR) should beEmptyMap()
            result.getProjects().map { it.id } should containExactlyInAnyOrder(
                projectIdsOf(SbomFixtures.CYCLONEDX_1_4_JSON) + projectIdsOf(SbomFixtures.CYCLONEDX_1_6_XML)
            )
            result.getProjects().map { it.definitionFilePath }.toSet() should containExactly("sbom-sources.yml")
            result.getPackages().map { it.metadata.id } should contain(Identifier("Maven:jakarta.mail:jakarta.mail-api:2.1.3"))
        }

        "send the API key provided by the default authenticator" {
            Authenticator.setDefault(object : Authenticator() {
                override fun getPasswordAuthentication(): PasswordAuthentication? =
                    PasswordAuthentication("", "api-key".toCharArray()).takeIf {
                        requestingURL.toString().startsWith(server.baseUrl)
                    }
            })

            val dir = tempdir()
            File(dir, "sbom-sources.yml").writeText("sources:\n  - ${server.baseUrl}/projects/$UUID\n")
            server.requests.clear()

            analyze(dir).getAnalyzerIssues(minSeverity = Severity.ERROR) should beEmptyMap()

            server.requests.map { it.headers["x-api-key"] }.toSet() should containExactly("api-key")
        }

        "report a source that cannot be retrieved and analyze the others" {
            val dir = tempdir()
            File(dir, "product.sbom-sources.yaml").writeText(
                """
                sources:
                  - ${server.baseUrl}/releases/missing.cdx.json
                  - ${server.baseUrl}/releases/product.spdx3.json
                """.trimIndent()
            )

            val result = analyze(dir)

            val failedProject = sanitizedIdentifier("SBOM", "", "${server.baseUrl}/releases/missing.cdx.json", "")
            val issues = result.getAnalyzerIssues(minSeverity = Severity.ERROR)
            issues.keys should containExactly(failedProject)
            issues.getValue(failedProject).single().message should containString("failed with status 404")

            result.getProjects().map { it.id } should containExactlyInAnyOrder(
                projectIdsOf(SbomFixtures.SPDX_3_0_SBOMIFY) + failedProject
            )
            result.getProject(failedProject)?.homepageUrl shouldBe "${server.baseUrl}/releases/missing.cdx.json"
        }

        "analyze SBOM files and source files side by side" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_6_JSON)
            File(dir, "sbom-sources.yml").writeText("sources:\n  - ${server.baseUrl}/projects/$UUID\n")

            val result = analyze(dir)

            result.getProjects().map { it.definitionFilePath } should containExactlyInAnyOrder(
                "sbom-sources.yml",
                SbomFixtures.CYCLONEDX_1_6_JSON.substringAfterLast('/')
            )
        }

        "report an invalid source file" {
            val dir = tempdir()
            File(dir, "sbom-sources.yml").writeText("sources:\n  - url: ${server.baseUrl}/bom.json\n    version: 1\n")

            val issues = analyze(dir).getAnalyzerIssues(minSeverity = Severity.ERROR).values.flatten()

            issues.single().message should containString("Invalid SBOM source file 'sbom-sources.yml'")
        }

        "ignore source files if no source file patterns are configured" {
            val dir = tempdir()
            File(dir, "sbom-sources.yml").writeText("sources:\n  - ${server.baseUrl}/projects/$UUID\n")

            analyze(dir, mapOf("sourceFilePatterns" to "")).getProjects() shouldBe emptySet()
        }
    }
})

/** Return the identifiers of the projects created from the given SBOM [fixture] when it is analyzed as a file. */
private fun projectIdsOf(fixture: String): List<Identifier> {
    val dir = createTempDirectory("sbom-fixture").toFile()
    return try {
        SbomFixtures.copyTo(dir, fixture)
        analyze(dir).getProjects().map { it.id }
    } finally {
        dir.deleteRecursively()
    }
}

private fun analyze(dir: File, options: Map<String, String> = emptyMap()): OrtResult {
    val config = AnalyzerConfiguration(
        enabledPackageManagers = listOf("SBOM"),
        packageManagers = mapOf("SBOM" to PackageManagerConfiguration(options = options))
    )

    val analyzer = Analyzer(config)
    return analyzer.analyze(analyzer.findManagedFiles(dir, listOf(SbomFactory())))
}
