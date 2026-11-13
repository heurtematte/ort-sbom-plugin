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
import java.nio.file.FileSystems
import java.nio.file.PathMatcher

import org.eclipse.apoapsis.sbom.parser.SbomDocument
import org.eclipse.apoapsis.sbom.parser.SbomParser
import org.eclipse.apoapsis.sbom.sources.FetchedSbom
import org.eclipse.apoapsis.sbom.sources.SbomFetcher
import org.eclipse.apoapsis.sbom.sources.SbomProjectMetadata
import org.eclipse.apoapsis.sbom.sources.SbomSource
import org.eclipse.apoapsis.sbom.sources.SbomSourceFile

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
import org.ossreviewtoolkit.utils.common.collectMessages
import org.ossreviewtoolkit.utils.ort.DeclaredLicenseProcessor
import org.ossreviewtoolkit.utils.ort.createOrtTempDir

import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(Sbom::class.java)

/** The type of the projects created from SBOMs, and of packages that cannot be identified by a purl. */
const val SBOM_PROJECT_TYPE = "SBOM"

/** The default file name patterns of SBOMs. */
private const val DEFAULT_DEFINITION_FILE_PATTERNS =
    "*.cdx.json,*.cdx.xml,*.cyclonedx.json,*.cyclonedx.xml,*-cyclonedx.json,*-cyclonedx.xml,bom.json,bom.xml," +
        "*.bom.json,*.bom.xml,sbom.json,sbom.xml,*.sbom.json,*.sbom.xml,*.spdx.json,*.spdx.yaml,*.spdx.yml,*.spdx.xml," +
        "*.spdx,*.spdx3.json,*.spdx.jsonld"

/** The default file name patterns of SBOM source files. */
private const val DEFAULT_SOURCE_FILE_PATTERNS =
    "sbom-sources.yml,sbom-sources.yaml,*.sbom-sources.yml,*.sbom-sources.yaml"

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
     * The file name patterns of SBOM source files. These YAML files list remote sources of SBOMs, such as
     * Dependency-Track projects, sbomify components or products, or URLs of SBOM documents, which are retrieved and
     * analyzed.
     */
    @OrtPluginOption(defaultValue = DEFAULT_SOURCE_FILE_PATTERNS)
    val sourceFilePatterns: List<String>,

    /**
     * Whether components that are not reachable from the root component in the dependency graph of the SBOM, for
     * instance because the SBOM does not contain dependency relationships, are added as direct dependencies of the
     * project. If disabled, such components are dropped.
     */
    @OrtPluginOption(defaultValue = "true")
    val attachUnreferencedComponents: Boolean,

    /** How licenses that the SBOM declares as concluded are mapped. */
    @OrtPluginOption(defaultValue = "DECLARED")
    val concludedLicenseHandling: ConcludedLicenseHandling,

    /**
     * Whether packages for which the SBOM gives no source artifact get the one derived from their package URL, for
     * registries whose layout makes it predictable: the sources JAR of Maven packages and the tarball of npm packages,
     * like the package managers of ORT. This lets the scanner get the sources of packages without a usable VCS.
     */
    @OrtPluginOption(defaultValue = "true")
    val deriveSourceArtifacts: Boolean,

    /**
     * Whether the retrieval of the sources of an SBOM source file stops at the first source that cannot be retrieved,
     * for instance because its server is not of the expected type or the credentials are missing. The remaining
     * sources are then reported as not retrieved, instead of being requested one by one.
     */
    @OrtPluginOption(defaultValue = "false")
    val failFast: Boolean
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
 *
 * SBOMs can also be retrieved at each analysis from the remote sources listed in SBOM source files (`sbom-sources.yml`):
 * projects of Dependency-Track, components or products of sbomify, or any URL. The credentials for these sources come
 * from the default authenticator: in ORT Server, the matching infrastructure service; with the ORT CLI, the `.netrc` file.
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
    private val sourceFilePatterns = config.sourceFilePatterns.map(String::trim).filter(String::isNotEmpty)

    override val globsForDefinitionFiles =
        listOf(
            (config.definitionFilePatterns.map(String::trim).filter(String::isNotEmpty) + sourceFilePatterns)
                .joinToString(",", "{", "}")
        )

    private val sourceFileMatcher: PathMatcher? = sourceFilePatterns.takeIf { it.isNotEmpty() }?.let { patterns ->
        FileSystems.getDefault().getPathMatcher(patterns.joinToString(",", "glob:{", "}"))
    }

    private val fetcher by lazy { SbomFetcher() }

    private val dependencyHandler = SbomDependencyHandler(config.concludedLicenseHandling, config.deriveSourceArtifacts)

    private val graphBuilder = DependencyGraphBuilder(dependencyHandler)

    /**
     * Keep only the [definitionFiles] that are SBOM source files or whose content is a supported SBOM, as the file name
     * patterns may also match other files.
     */
    override fun mapDefinitionFiles(
        analysisRoot: File,
        definitionFiles: List<File>,
        analyzerConfig: AnalyzerConfiguration
    ): List<File> =
        definitionFiles.filter { file ->
            (file.isSourceFile() || SbomParser.detectFormat(file.readHead()) != null).also { isSbom ->
                if (!isSbom) logger.info("Ignoring '{}' as it is not a supported SBOM.", file.relativeTo(analysisRoot))
            }
        }

    private fun File.isSourceFile(): Boolean = sourceFileMatcher?.matches(toPath().fileName) == true

    override fun resolveDependencies(
        analysisRoot: File,
        definitionFile: File,
        excludes: Excludes,
        includes: Includes,
        analyzerConfig: AnalyzerConfiguration,
        labels: Map<String, String>
    ): List<ProjectAnalyzerResult> {
        val definitionFilePath = VersionControlSystem.getPathInfo(definitionFile).path
            .ifEmpty { definitionFile.relativeTo(analysisRoot).invariantSeparatorsPath }
        val projectDir = definitionFile.parentFile

        if (definitionFile.isSourceFile()) return resolveSources(definitionFile, definitionFilePath, excludes, includes)

        val document = SbomParser.parse(definitionFile)
        logger.info(
            "Parsed {} {} document '{}' with {} components.",
            document.format.displayName,
            document.specVersion,
            definitionFile.name,
            document.components.size
        )

        return analyzeDocument(document, definitionFilePath, projectDir, definitionFile.name, excludes, includes)
    }

    /**
     * Retrieve the SBOMs of the sources listed in the given [sourceFile] and analyze them. A source that cannot be
     * retrieved results in a project with an error, so that the other sources are still analyzed, unless
     * [SbomConfig.failFast] is enabled: then the remaining sources are not retrieved.
     */
    private fun resolveSources(
        sourceFile: File,
        definitionFilePath: String,
        excludes: Excludes,
        includes: Includes
    ): List<ProjectAnalyzerResult> {
        val entries = SbomSourceFile.parse(sourceFile)
        require(entries.isNotEmpty()) { "The SBOM source file '${sourceFile.name}' does not list any sources." }

        val projectDir = sourceFile.parentFile
        val downloadDir = createOrtTempDir("sbom-sources")

        var failure: Throwable? = null

        return try {
            entries.flatMap { (source, projectMetadata) ->
                failure?.let { e ->
                    return@flatMap listOf(skippedSourceResult(source, definitionFilePath, projectDir, e))
                }

                val fetched = runCatching { fetcher.fetch(source, downloadDir) }.getOrElse { e ->
                    logger.error("Could not retrieve the SBOM of {}: {}", source.description, e.collectMessages())
                    if (config.failFast) failure = e
                    return@flatMap listOf(failedSourceResult(source, definitionFilePath, projectDir, e))
                }

                val document = runCatching { SbomParser.parse(fetched.file) }.getOrElse { e ->
                    return@flatMap listOf(failedSourceResult(source, definitionFilePath, projectDir, e))
                }

                logger.info(
                    "Parsed {} {} document of {} with {} components.",
                    document.format.displayName,
                    document.specVersion,
                    source.description,
                    document.components.size
                )

                analyzeDocument(document, definitionFilePath, projectDir, fetched.fallbackName(), excludes, includes)
                    .map { result -> result.copy(project = result.project.withMetadata(projectMetadata)) }
            }
        } finally {
            downloadDir.deleteRecursively()
        }
    }

    /** Create the result for a [source] that was not retrieved because an earlier source failed with [error]. */
    private fun skippedSourceResult(
        source: SbomSource,
        definitionFilePath: String,
        projectDir: File,
        error: Throwable
    ): ProjectAnalyzerResult =
        sourceResultWithIssue(
            source,
            definitionFilePath,
            projectDir,
            "The SBOM of ${source.description} was not retrieved, as the retrieval of an earlier source failed and " +
                "the option 'failFast' is enabled: ${error.collectMessages()}"
        )

    /** Create the result for a [source] whose SBOM could not be retrieved or parsed because of [error]. */
    private fun failedSourceResult(
        source: SbomSource,
        definitionFilePath: String,
        projectDir: File,
        error: Throwable
    ): ProjectAnalyzerResult =
        sourceResultWithIssue(
            source,
            definitionFilePath,
            projectDir,
            "Could not retrieve the SBOM of ${source.description}: ${error.collectMessages()}"
        )

    /** Create the result for a [source] without SBOM, with an error issue with the given [message]. */
    private fun sourceResultWithIssue(
        source: SbomSource,
        definitionFilePath: String,
        projectDir: File,
        message: String
    ): ProjectAnalyzerResult {
        val project = Project(
            id = dependencyHandler.uniqueProjectId(sanitizedIdentifier(SBOM_PROJECT_TYPE, "", source.url, "")),
            definitionFilePath = definitionFilePath,
            declaredLicenses = emptySet(),
            vcs = VcsInfo.EMPTY,
            vcsProcessed = processProjectVcs(projectDir),
            homepageUrl = source.url,
            scopeNames = emptySet()
        )

        val issue = Issue(source = descriptor.id, message = message, severity = Severity.ERROR)

        return ProjectAnalyzerResult(project, emptySet(), listOf(issue))
    }

    /**
     * Convert the given [document] into projects. Use the given [definitionFilePath] and [projectDir] for the projects,
     * and the given [fallbackName] for the project if the document describes no component and has no name.
     */
    @Suppress("LongParameterList")
    private fun analyzeDocument(
        document: SbomDocument,
        definitionFilePath: String,
        projectDir: File,
        fallbackName: String,
        excludes: Excludes,
        includes: Includes
    ): List<ProjectAnalyzerResult> {
        val documentIndex = dependencyHandler.register(document)

        val issues = document.warnings.mapTo(mutableListOf()) { warning ->
            Issue(source = descriptor.id, message = warning, severity = Severity.HINT)
        }

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
                syntheticProject(document, fallbackName, definitionFilePath, projectDir)
            } else {
                dependencyHandler.createProject(documentIndex, root, definitionFilePath, projectDir)
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

    private fun syntheticProject(
        document: SbomDocument,
        fallbackName: String,
        definitionFilePath: String,
        projectDir: File
    ): Project {
        val name = document.name?.takeUnless { it.isBlank() } ?: fallbackName
        return Project(
            id = dependencyHandler.uniqueProjectId(sanitizedIdentifier(SBOM_PROJECT_TYPE, "", name, "")),
            definitionFilePath = definitionFilePath,
            declaredLicenses = emptySet(),
            vcs = VcsInfo.EMPTY,
            vcsProcessed = processProjectVcs(projectDir),
            homepageUrl = ""
        )
    }
}

/** The name of the project created for a fetched SBOM that describes no component and has no name. */
private fun FetchedSbom.fallbackName(): String =
    listOfNotNull(name, version).joinToString(" ").ifEmpty { source.url }

/** Return this project with the values of the given [metadata] in place of those of the SBOM. */
private fun Project.withMetadata(metadata: SbomProjectMetadata): Project {
    if (metadata.isEmpty()) return this

    val licenses = metadata.declaredLicenses.ifEmpty { declaredLicenses }

    return copy(
        authors = metadata.authors.ifEmpty { authors },
        declaredLicenses = licenses,
        declaredLicensesProcessed = DeclaredLicenseProcessor.process(licenses),
        description = metadata.description ?: description,
        homepageUrl = metadata.homepageUrl ?: homepageUrl
    )
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
