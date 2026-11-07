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

import java.io.File

import org.eclipse.apoapsis.sbom.parser.SbomDocument
import org.eclipse.apoapsis.sbom.parser.SbomParser

import org.ossreviewtoolkit.analyzer.PackageManager
import org.ossreviewtoolkit.analyzer.PackageManagerFactory
import org.ossreviewtoolkit.analyzer.PackageManagerResult
import org.ossreviewtoolkit.downloader.VersionControlSystem
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.ProjectAnalyzerResult
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.model.config.Excludes
import org.ossreviewtoolkit.model.config.Includes
import org.ossreviewtoolkit.model.utils.DependencyGraphBuilder
import org.ossreviewtoolkit.model.utils.isScopeIncluded
import org.ossreviewtoolkit.plugins.api.OrtPlugin
import org.ossreviewtoolkit.plugins.api.OrtPluginOption
import org.ossreviewtoolkit.plugins.api.PluginDescriptor

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(Sbom::class.java)

/** The type of the projects created from SBOMs, and of packages that cannot be identified by a purl. */
const val SBOM_PROJECT_TYPE = "SBOM"

/** The default file name patterns of SBOMs. */
private const val DEFAULT_DEFINITION_FILE_PATTERNS =
    "*.cdx.json,*.cdx.xml,*.cyclonedx.json,*.cyclonedx.xml,*-cyclonedx.json,*-cyclonedx.xml,bom.json,bom.xml," +
        "*.bom.json,*.bom.xml,sbom.json,sbom.xml,*.sbom.json,*.sbom.xml,*.spdx.json,*.spdx.yaml,*.spdx.yml,*.spdx.xml," +
        "*.spdx,*.spdx3.json,*.spdx.jsonld"

/** How licenses that an SBOM declares as concluded are mapped to ORT. */
enum class ConcludedLicenseHandling {
    /** Map them to the concluded license of the package, which takes precedence over declared licenses. */
    CONCLUDED,

    /** Use them as declared licenses of packages that do not declare a license otherwise. */
    DECLARED,

    /** Ignore them. */
    IGNORE
}

data class SbomConfig(
    /**
     * The file name patterns of the SBOMs to analyze. Files matching these patterns are analyzed only if their content
     * is a supported SBOM.
     */
    @OrtPluginOption(defaultValue = DEFAULT_DEFINITION_FILE_PATTERNS)
    val definitionFilePatterns: List<String>,

    /**
     * Whether components that are not reachable from the root component in the dependency graph of the SBOM, for
     * instance because the SBOM does not contain dependency relationships, are added as direct dependencies of the
     * project. If disabled, such components are dropped.
     */
    @OrtPluginOption(defaultValue = "true")
    val attachUnreferencedComponents: Boolean,

    /** How licenses that the SBOM declares as concluded are mapped. */
    @OrtPluginOption(defaultValue = "DECLARED")
    val concludedLicenseHandling: ConcludedLicenseHandling
)

/**
 * A "fake" package manager that ingests existing SBOMs instead of analyzing build files. It supports CycloneDX (JSON
 * and XML) and SPDX (2.x as JSON, YAML, tag-value, or XML, and 3.0 as JSON-LD) documents.
 *
 * Each component an SBOM describes (the CycloneDX `metadata.component`, or the packages an SPDX document `DESCRIBES`)
 * becomes a project, and all other components become packages. The dependency graph of the SBOM is preserved; if
 * components are not reachable from a described component, they are attached as direct dependencies of the project
 * (see the "attachUnreferencedComponents" option). If an SBOM describes no component, a project named after the
 * document is created.
 *
 * Packages are identified by their package URL if they have one, so that they get the same identifiers as packages
 * found by the native package managers of ORT; this allows advisors, package curations, and rules to work on them.
 */
@OrtPlugin(
    id = "SBOM",
    displayName = "SBOM",
    summary = "A package manager that ingests existing SBOMs in CycloneDX or SPDX format.",
    factory = PackageManagerFactory::class
)
class Sbom(
    override val descriptor: PluginDescriptor = SbomFactory.descriptor,
    private val config: SbomConfig
) : PackageManager(SBOM_PROJECT_TYPE) {
    override val globsForDefinitionFiles =
        listOf(config.definitionFilePatterns.map(String::trim).filter(String::isNotEmpty).joinToString(",", "{", "}"))

    private val dependencyHandler = SbomDependencyHandler(config.concludedLicenseHandling)

    private val graphBuilder = DependencyGraphBuilder(dependencyHandler)

    /**
     * Keep only the [definitionFiles] whose content is a supported SBOM, as the file name patterns may also match
     * other files.
     */
    override fun mapDefinitionFiles(
        analysisRoot: File,
        definitionFiles: List<File>,
        analyzerConfig: AnalyzerConfiguration
    ): List<File> =
        definitionFiles.filter { file ->
            (SbomParser.detectFormat(file.readHead()) != null).also { isSbom ->
                if (!isSbom) logger.info("Ignoring '{}' as it is not a supported SBOM.", file.relativeTo(analysisRoot))
            }
        }

    override fun resolveDependencies(
        analysisRoot: File,
        definitionFile: File,
        excludes: Excludes,
        includes: Includes,
        analyzerConfig: AnalyzerConfiguration,
        labels: Map<String, String>
    ): List<ProjectAnalyzerResult> {
        val document = SbomParser.parse(definitionFile)
        val documentIndex = dependencyHandler.register(document)

        logger.info(
            "Parsed {} {} document '{}' with {} components.",
            document.format.displayName,
            document.specVersion,
            definitionFile.name,
            document.components.size
        )

        val issues = document.warnings.mapTo(mutableListOf()) { warning ->
            Issue(source = descriptor.id, message = warning, severity = Severity.HINT)
        }

        val definitionFilePath = VersionControlSystem.getPathInfo(definitionFile).path
            .ifEmpty { definitionFile.relativeTo(analysisRoot).invariantSeparatorsPath }

        val roots = document.roots.ifEmpty { listOf(SYNTHETIC_ROOT_REF) }
        val directDependencies = roots.associateWith { root -> document.directDependenciesOf(root) }.toMutableMap()

        val (unreferenced, unreachableCount) =
            document.unreferencedComponents(directDependencies.values.flatten().map { it.target })
        if (unreferenced.isNotEmpty()) {
            if (config.attachUnreferencedComponents) {
                val firstRoot = roots.first()
                directDependencies[firstRoot] = directDependencies.getValue(firstRoot) +
                    unreferenced.map { SbomEdge(it, null) }

                // Do not report this for SBOMs without any dependency relationships, where it is expected.
                if (document.relationships.isNotEmpty()) {
                    issues += Issue(
                        source = descriptor.id,
                        message = "$unreachableCount component(s) are not reachable from a described component " +
                            "in the dependency graph of the SBOM. They were added to the project through " +
                            "${unreferenced.size} direct dependencies.",
                        severity = Severity.HINT
                    )
                }
            } else {
                issues += Issue(
                    source = descriptor.id,
                    message = "Ignoring $unreachableCount component(s) that are not reachable from a described " +
                        "component in the dependency graph of the SBOM.",
                    severity = Severity.WARNING
                )
            }
        }

        return roots.map { root ->
            val project = if (root == SYNTHETIC_ROOT_REF) {
                syntheticProject(document, definitionFile, definitionFilePath)
            } else {
                dependencyHandler.createProject(documentIndex, root, definitionFilePath, definitionFile.parentFile)
            }

            directDependencies.getValue(root)
                .groupBy { edge -> edge.scope ?: document.components[edge.target]?.scope ?: document.defaultScope }
                .toSortedMap()
                .filterKeys { scope -> isScopeIncluded(scope, excludes, includes) }
                .forEach { (scope, edges) ->
                    graphBuilder.addDependencies(
                        project.id,
                        scope,
                        edges.map { SbomNode(documentIndex, it.target) }
                    )
                }

            ProjectAnalyzerResult(
                project = project.copy(scopeNames = graphBuilder.scopesFor(project.id)),
                packages = emptySet(),
                issues = issues.takeIf { root == roots.first() }.orEmpty()
            )
        }
    }

    override fun createPackageManagerResult(projectResults: Map<File, List<ProjectAnalyzerResult>>) =
        PackageManagerResult(projectResults, graphBuilder.build(), graphBuilder.packages())

    private fun syntheticProject(document: SbomDocument, definitionFile: File, definitionFilePath: String): Project {
        val name = document.name?.takeUnless { it.isBlank() } ?: definitionFile.name
        return Project(
            id = sanitizedIdentifier(SBOM_PROJECT_TYPE, "", name, ""),
            definitionFilePath = definitionFilePath,
            declaredLicenses = emptySet(),
            vcs = VcsInfo.EMPTY,
            vcsProcessed = processProjectVcs(definitionFile.parentFile),
            homepageUrl = ""
        )
    }
}

/** The ref of the artificial root used for SBOMs that do not describe a component. */
internal const val SYNTHETIC_ROOT_REF = "\u0000root"

/** An edge to a direct dependency with the ref [target] and an optional [scope]. */
internal data class SbomEdge(val target: String, val scope: String?)

/**
 * Return the direct dependencies of the component with the given [root] ref. For the [SYNTHETIC_ROOT_REF], these are
 * the components no other component depends on.
 */
private fun SbomDocument.directDependenciesOf(root: String): List<SbomEdge> =
    if (root == SYNTHETIC_ROOT_REF) {
        val targets = relationships.values.flatten().mapTo(mutableSetOf()) { it.target }
        components.keys.filter { it !in targets }.map { SbomEdge(it, null) }
    } else {
        dependenciesOf(root).filter { it.target in components }.map { SbomEdge(it.target, it.scope) }
    }

/**
 * Determine the components that are neither roots nor reachable from the given [directDependencies]. To keep the
 * structure of unreferenced subgraphs, return only their entry points (components that no other unreferenced
 * component depends on, plus one component per cycle that has no such entry point), together with the total number
 * of unreachable components.
 */
private fun SbomDocument.unreferencedComponents(directDependencies: List<String>): Pair<List<String>, Int> {
    val reachable = mutableSetOf<String>()

    fun visit(start: Collection<String>) {
        val queue = ArrayDeque(start.filter { reachable.add(it) })
        while (queue.isNotEmpty()) {
            dependenciesOf(queue.removeFirst()).forEach { edge ->
                if (edge.target in components && reachable.add(edge.target)) queue += edge.target
            }
        }
    }

    visit(roots + directDependencies)

    val unreachable = components.keys.filterNot { it in reachable }
    if (unreachable.isEmpty()) return emptyList<String>() to 0

    val targetsOfUnreachable = unreachable.flatMapTo(mutableSetOf()) { ref -> dependenciesOf(ref).map { it.target } }
    val entryPoints = unreachable.filterNot { it in targetsOfUnreachable }.toMutableList()
    visit(entryPoints)

    // Components in cycles without an entry point remain unreachable; pick them one by one.
    unreachable.forEach { ref ->
        if (ref !in reachable) {
            entryPoints += ref
            visit(listOf(ref))
        }
    }

    return entryPoints to unreachable.size
}

/** Read the beginning of this file for format detection. */
private fun File.readHead(): ByteArray =
    inputStream().use { input -> input.readNBytes(HEAD_BYTES) }

private const val HEAD_BYTES = 16 * 1024
