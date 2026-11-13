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
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.collections.containExactly
import io.kotest.matchers.collections.containExactlyInAnyOrder
import io.kotest.matchers.collections.haveSize
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.maps.beEmpty as beEmptyMap
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.string.contain

import java.io.File

import org.eclipse.apoapsis.sbom.parser.SbomFixtures

import org.ossreviewtoolkit.analyzer.Analyzer
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.OrtResult
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.model.config.Excludes
import org.ossreviewtoolkit.model.config.PackageManagerConfiguration
import org.ossreviewtoolkit.model.config.RepositoryConfiguration
import org.ossreviewtoolkit.model.config.ScopeExclude
import org.ossreviewtoolkit.model.config.ScopeExcludeReason

class SbomTest : WordSpec({
    "The SBOM package manager" should {
        SbomFixtures.ALL.forEach { (fixture, expected) ->
            "analyze '$fixture' (${expected.first.displayName} ${expected.second}) without errors" {
                val dir = tempdir()
                SbomFixtures.copyTo(dir, fixture, "sbom.${expected.first.fileExtension}")

                val result = analyze(dir)

                result.getProjects() shouldNot beEmpty()
                result.getAnalyzerIssues(minSeverity = Severity.ERROR) should beEmptyMap()
            }
        }

        "encode colons in identifiers but keep the original package URL" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_7_DEBIAN, "sbom.cdx.json")

            val attr = analyze(dir).getPackages().map { it.metadata }.single { it.id.name == "attr" }

            attr.id shouldBe Identifier("deb:debian:attr:1%3A2.4.47-2+b1")
            attr.purl should contain("@1%3A2.4.47-2%2Bb1")
        }

        "give unique identifiers to described components with the same coordinates" {
            val dir = tempdir()
            File(dir, "sbom.spdx").writeText(
                """
                SPDXVersion: SPDX-2.3
                DataLicense: CC0-1.0
                SPDXID: SPDXRef-DOCUMENT
                DocumentName: release
                DocumentNamespace: https://example.org/release
                Creator: Tool: test

                PackageName: kube-apiserver.tar
                SPDXID: SPDXRef-amd64
                PackageDownloadLocation: NOASSERTION

                PackageName: kube-apiserver.tar
                SPDXID: SPDXRef-arm64
                PackageDownloadLocation: NOASSERTION

                Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-amd64
                Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-arm64
                """.trimIndent()
            )

            val result = analyze(dir)

            result.getProjects().map { it.id.name } should containExactlyInAnyOrder(
                "kube-apiserver.tar", "kube-apiserver.tar (SPDXRef-arm64)"
            )
            result.getAnalyzerIssues(minSeverity = Severity.ERROR) should beEmptyMap()
        }

        "analyze a product exported by sbomify as a project composed of its components" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.SPDX_3_0_SBOMIFY, "sbom.spdx3.json")

            val result = analyze(dir)

            val project = result.getProjects().single()
            project.id.name shouldBe "sbomify - latest"
            // The product lists each of its three components twice with the same coordinates.
            result.dependencyNavigator.projectDependencies(project).map { it.name } should containExactlyInAnyOrder(
                "Container", "Frontend Stack", "Python Stack"
            )
        }

        "create a project named after the document for an SBOM without root component" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_0_XML, "bom.xml")

            val result = analyze(dir)

            result.getProjects().single().id shouldBe Identifier("SBOM::bom.xml:")
            result.getPackages() shouldNot beEmpty()
        }

        "create a project with its dependency tree from a CycloneDX SBOM" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_4_JSON)

            val result = analyze(dir)

            val project = result.getProjects().single()
            project.id shouldBe Identifier("SBOM:org.eclipse.angus:imap:2.0.3")
            project.definitionFilePath shouldBe "angus-imap-2.0.3-v1.4.cdx.json"
            project.declaredLicenses should containExactlyInAnyOrder(
                "EPL-2.0", "GPL-2.0-with-classpath-exception", "BSD-3-Clause"
            )

            result.dependencyNavigator.scopeNames(project) should containExactly("required")
            result.directDependencies(project, "required") should containExactly(MAIL_API, ANGUS_CORE)
            result.getDependencies(ANGUS_CORE) shouldContainAll setOf(MAIL_API)

            val mailApi = result.getPackages().single { it.metadata.id == MAIL_API }.metadata
            mailApi.purl shouldBe "pkg:maven/jakarta.mail/jakarta.mail-api@2.1.3?type=jar"
            mailApi.vcsProcessed.url shouldBe "https://github.com/jakartaee/mail-api.git"
            mailApi.sourceArtifact.url shouldBe
                "https://repo.maven.apache.org/maven2/jakarta/mail/jakarta.mail-api/2.1.3/jakarta.mail-api-2.1.3-" +
                "sources.jar"
            mailApi.declaredLicenses should containExactlyInAnyOrder(
                "EPL-2.0", "GPL-2.0-with-classpath-exception", "BSD-3-Clause"
            )
        }

        "not derive source artifacts from package URLs if disabled" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_4_JSON)

            val result = analyze(dir, mapOf("deriveSourceArtifacts" to "false"))

            result.getPackages().single { it.metadata.id == MAIL_API }.metadata.sourceArtifact.url shouldBe ""
        }

        "produce the same result for the JSON and XML serializations of a CycloneDX SBOM" {
            val jsonDir = tempdir().also { SbomFixtures.copyTo(it, SbomFixtures.CYCLONEDX_1_6_JSON, "bom.cdx.json") }
            val xmlDir = tempdir().also { SbomFixtures.copyTo(it, SbomFixtures.CYCLONEDX_1_6_XML, "bom.cdx.xml") }

            val jsonResult = analyze(jsonDir)
            val xmlResult = analyze(xmlDir)

            val jsonProject = jsonResult.getProjects().single()
            val xmlProject = xmlResult.getProjects().single()
            xmlProject.id shouldBe jsonProject.id
            xmlResult.getPackages().map { it.metadata.id } shouldBe jsonResult.getPackages().map { it.metadata.id }
            xmlResult.dependencyNavigator.projectDependencies(xmlProject) shouldBe
                jsonResult.dependencyNavigator.projectDependencies(jsonProject)
        }

        "attach components without dependency relationships to the project" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_6_FLAT)

            val result = analyze(dir)

            val project = result.getProjects().single()
            project.id.type shouldBe SBOM_PROJECT_TYPE
            result.getPackages().map { it.metadata.id.name } should containExactlyInAnyOrder(
                "JDK Component", "JRE Component", "STATIC-LIBS Component", "DEBUGIMAGE Component",
                "TESTIMAGE Component"
            )
            result.getPackages().map { it.metadata.id.type }.toSet() should containExactly(SBOM_PROJECT_TYPE)
            result.getAnalyzerIssues().values.flatten() should beEmpty()
        }

        "report or drop components that are not reachable in the dependency graph" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_5_JSON_EXCERPT)

            val attached = analyze(dir)
            val dropped = analyze(dir, options = mapOf("attachUnreferencedComponents" to "false"))

            attached.getPackages() should haveSize(25)
            attached.getAnalyzerIssues().values.flatten().single().severity shouldBe Severity.HINT

            dropped.getPackages().size shouldBe attached.getPackages().size -
                attached.unreferencedCount()
            with(dropped.getAnalyzerIssues().values.flatten().single()) {
                severity shouldBe Severity.WARNING
                message should contain("Ignoring")
            }
        }

        "create the same projects and packages from all serializations of an SPDX SBOM" {
            val results = listOf(
                SbomFixtures.SPDX_2_3_JSON,
                SbomFixtures.SPDX_2_3_YAML,
                SbomFixtures.SPDX_2_3_TAG_VALUE,
                SbomFixtures.SPDX_3_0_JSON_LD
            ).map { fixture -> analyze(tempdir().also { SbomFixtures.copyTo(it, fixture) }) }

            results.forEach { result ->
                val project = result.getProjects().single()
                project.id shouldBe Identifier("SBOM:eclipse-cbi:p2repo-sbom:main")
                result.getPackages() should haveSize(20)
                result.getPackages().map { it.metadata.id } shouldBe
                    results.first().getPackages().map { it.metadata.id }
                result.dependencyNavigator.scopeNames(project) should containExactly("dependencies")
            }

            results.first().getPackages().map { it.metadata.id }.shouldContainAll(TYCHO_DIRECTOR)
        }

        "map licenses concluded by the SBOM according to the configuration" {
            fun licensesOf(result: OrtResult) =
                result.getPackages().single { it.metadata.id == TYCHO_DIRECTOR }.metadata

            val dir = tempdir()
            File(dir, "sbom.spdx.json").writeText(
                SbomFixtures.bytes(SbomFixtures.SPDX_2_3_JSON).decodeToString().replace(
                    "\"SPDXID\": \"SPDXRef-maven-org.eclipse.tycho-tycho-p2-director-plugin-88b080\",",
                    "\"SPDXID\": \"SPDXRef-maven-org.eclipse.tycho-tycho-p2-director-plugin-88b080\", " +
                        "\"licenseConcluded\": \"EPL-2.0\","
                )
            )

            licensesOf(analyze(dir)).declaredLicenses should containExactly("EPL-2.0")

            with(licensesOf(analyze(dir, options = mapOf("concludedLicenseHandling" to "CONCLUDED")))) {
                declaredLicenses should beEmpty()
                concludedLicense.toString() shouldBe "EPL-2.0"
            }

            licensesOf(analyze(dir, options = mapOf("concludedLicenseHandling" to "IGNORE"))).declaredLicenses should
                beEmpty()
        }

        "analyze all SBOMs of a directory and ignore files that are not SBOMs" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_4_JSON)
            SbomFixtures.copyTo(dir.resolve("spdx").apply { mkdirs() }, SbomFixtures.SPDX_2_3_JSON)
            File(dir, "bom.json").writeText("""{"name": "not an SBOM"}""")

            val result = analyze(dir)

            result.getProjects().map { it.id.name } should containExactlyInAnyOrder("imap", "p2repo-sbom")
            result.getAnalyzerIssues().values.flatten() should beEmpty()
        }

        "apply scope excludes" {
            val dir = tempdir()
            SbomFixtures.copyTo(dir, SbomFixtures.CYCLONEDX_1_4_JSON)

            val result = analyze(
                dir,
                repositoryConfiguration = RepositoryConfiguration(
                    excludes = Excludes(
                        scopes = listOf(ScopeExclude("required", ScopeExcludeReason.TEST_DEPENDENCY_OF))
                    )
                ),
                skipExcluded = true
            )

            result.getProjects().single().scopeNames.orEmpty() should beEmpty()
            result.getPackages() should beEmpty()
        }
    }
})

private val MAIL_API = Identifier("Maven:jakarta.mail:jakarta.mail-api:2.1.3")
private val ANGUS_CORE = Identifier("Maven:org.eclipse.angus:angus-core:2.0.3")
private val TYCHO_DIRECTOR = Identifier("Maven:org.eclipse.tycho:tycho-p2-director-plugin:")

/** Run the ORT Analyzer with the SBOM package manager on the given [dir]. */
private fun analyze(
    dir: File,
    options: Map<String, String> = emptyMap(),
    repositoryConfiguration: RepositoryConfiguration = RepositoryConfiguration(),
    skipExcluded: Boolean = false
): OrtResult {
    val config = AnalyzerConfiguration(
        enabledPackageManagers = listOf("SBOM"),
        packageManagers = mapOf("SBOM" to PackageManagerConfiguration(options = options)),
        skipExcluded = skipExcluded
    )

    val analyzer = Analyzer(config)
    val info = analyzer.findManagedFiles(dir, listOf(SbomFactory()), repositoryConfiguration)
    return analyzer.analyze(info)
}

private fun OrtResult.directDependencies(project: Project, scope: String): List<Identifier> =
    dependencyNavigator.directDependencies(project, scope).map { it.id }.toList()

/** Return the number of components the hint about unreferenced components reports. */
private fun OrtResult.unreferencedCount(): Int =
    getAnalyzerIssues().values.flatten().single().message.substringBefore(' ').toInt()
