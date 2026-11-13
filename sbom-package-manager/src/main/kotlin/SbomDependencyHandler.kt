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

import org.eclipse.apoapsis.sbom.parser.SbomComponent
import org.eclipse.apoapsis.sbom.parser.SbomDocument
import org.eclipse.apoapsis.sbom.parser.SbomHash

import org.ossreviewtoolkit.analyzer.PackageManager
import org.ossreviewtoolkit.model.Hash
import org.ossreviewtoolkit.model.HashAlgorithm
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.PackageLinkage
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.RemoteArtifact
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.utils.DependencyHandler
import org.ossreviewtoolkit.model.utils.toPackageUrl
import org.ossreviewtoolkit.utils.spdxexpression.SpdxExpression

/** A node of the dependency graph: the component with the given [ref] in the document with index [document]. */
internal data class SbomNode(val document: Int, val ref: String)

/**
 * The mapping from package URL types to the identifier types used by the package managers of ORT, so that packages
 * from SBOMs get the same identifiers as packages found by analyzing build files.
 */
private val PURL_TYPE_TO_ORT_TYPE = mapOf(
    "bazel" to "Bazel",
    "bower" to "Bower",
    "cargo" to "Crate",
    "carthage" to "Carthage",
    "cocoapods" to "Pod",
    "composer" to "Composer",
    "conan" to "Conan",
    "gem" to "Gem",
    "golang" to "Go",
    "hackage" to "Hackage",
    "hex" to "Hex",
    "maven" to "Maven",
    "npm" to "NPM",
    "nuget" to "NuGet",
    "pub" to "Pub",
    "pypi" to "PyPI",
    "swift" to "Swift"
)

/**
 * A [DependencyHandler] for the components of [SbomDocument]s. As one package manager instance processes multiple
 * documents, documents are [registered][register] and nodes refer to them by index.
 */
internal class SbomDependencyHandler(
    private val concludedLicenseHandling: ConcludedLicenseHandling
) : DependencyHandler<SbomNode> {
    private val documents = mutableListOf<SbomDocument>()
    private val identifiers = mutableMapOf<SbomNode, Identifier>()
    private val projectIds = mutableSetOf<Identifier>()

    /** Register the given [document] and return its index. */
    fun register(document: SbomDocument): Int {
        documents += document
        return documents.lastIndex
    }

    private fun component(node: SbomNode): SbomComponent = documents[node.document].components.getValue(node.ref)

    private fun isProject(node: SbomNode): Boolean = node.ref in documents[node.document].roots

    override fun identifierFor(dependency: SbomNode): Identifier =
        identifiers.getOrPut(dependency) {
            val id = component(dependency).toIdentifier()
            if (isProject(dependency)) uniqueProjectId(id.copy(type = SBOM_PROJECT_TYPE), dependency.ref) else id
        }

    /**
     * Return the given project [id], or, if another project already has this identifier, an identifier whose name is
     * qualified with the given [ref] or a number, as ORT requires projects to have unique identifiers. This happens for
     * instance for SBOMs that describe the same artifact for different architectures.
     */
    fun uniqueProjectId(id: Identifier, ref: String? = null): Identifier {
        if (projectIds.add(id)) return id

        val qualifiers = sequenceOf(ref?.substringAfterLast('#')) + generateSequence(2) { it + 1 }.map { "#$it" }
        return qualifiers.filterNotNull().map { qualifier ->
            sanitizedIdentifier(id.type, id.namespace, "${id.name} ($qualifier)", id.version)
        }.first { projectIds.add(it) }
    }

    override fun dependenciesFor(dependency: SbomNode): List<SbomNode> {
        val document = documents[dependency.document]
        return document.dependenciesOf(dependency.ref)
            .filter { it.target in document.components }
            .map { SbomNode(dependency.document, it.target) }
    }

    override fun linkageFor(dependency: SbomNode): PackageLinkage =
        if (isProject(dependency)) PackageLinkage.PROJECT_DYNAMIC else PackageLinkage.DYNAMIC

    override fun createPackage(dependency: SbomNode, issues: MutableCollection<Issue>): Package? =
        if (isProject(dependency)) null else component(dependency).toPackage(identifierFor(dependency))

    /**
     * Create the [Project] for the root component with the given [ref] in the document with the given
     * [documentIndex]. Use the given [definitionFilePath] and [projectDir] to set up the location of the project.
     */
    fun createProject(documentIndex: Int, ref: String, definitionFilePath: String, projectDir: File): Project {
        val node = SbomNode(documentIndex, ref)
        val component = component(node)
        val vcs = component.vcsInfo()

        return Project(
            id = identifierFor(node),
            cpe = component.cpe,
            definitionFilePath = definitionFilePath,
            authors = component.authorsOrSupplier(),
            declaredLicenses = component.declaredLicenses.ifEmpty {
                setOfNotNull(
                    component.concludedLicense.takeIf {
                        concludedLicenseHandling != ConcludedLicenseHandling.IGNORE
                    }
                )
            },
            vcs = vcs,
            // ORT requires the processed VCS of a project to match the analyzed repository, so the VCS declared in the
            // SBOM is only kept as the unprocessed VCS information.
            vcsProcessed = PackageManager.processProjectVcs(projectDir),
            description = component.description.orEmpty(),
            homepageUrl = component.homepageUrl.orEmpty()
        )
    }

    private fun SbomComponent.toPackage(id: Identifier): Package {
        val hash = hashes.bestHash()
        val vcs = vcsInfo()
        val concluded = concludedLicense?.takeIf { concludedLicenseHandling == ConcludedLicenseHandling.CONCLUDED }
            ?.let { runCatching { SpdxExpression.parse(it) }.getOrNull() }
        val declared = declaredLicenses.ifEmpty {
            setOfNotNull(concludedLicense.takeIf { concludedLicenseHandling == ConcludedLicenseHandling.DECLARED })
        }

        return Package(
            id = id,
            purl = purl.orEmpty(),
            cpe = cpe,
            authors = authorsOrSupplier(),
            declaredLicenses = declared,
            concludedLicense = concluded,
            description = description.orEmpty(),
            homepageUrl = homepageUrl.orEmpty(),
            binaryArtifact = downloadUrl?.let { RemoteArtifact(it, hash) } ?: RemoteArtifact.EMPTY,
            sourceArtifact = sourceDownloadUrl?.let { RemoteArtifact(it, if (downloadUrl == null) hash else Hash.NONE) }
                ?: RemoteArtifact.EMPTY,
            vcs = vcs,
            vcsProcessed = PackageManager.processPackageVcs(vcs, homepageUrl.orEmpty())
        )
    }
}

/**
 * Return the [Identifier] of this component. If it has a valid package URL, the identifier is derived from it, using
 * the identifier types of the ORT package managers; otherwise, it is built from the coordinates of the component.
 */
internal fun SbomComponent.toIdentifier(): Identifier {
    val packageUrl = purl.toPackageUrl()

    if (packageUrl != null) {
        // Like ORT, use the last segment of the combined namespace and name as name.
        val combinedName = listOfNotNull(packageUrl.namespace, packageUrl.name).joinToString("/")
        return sanitizedIdentifier(
            type = PURL_TYPE_TO_ORT_TYPE[packageUrl.type] ?: packageUrl.type,
            namespace = combinedName.substringBeforeLast("/", ""),
            name = combinedName.substringAfterLast("/"),
            version = packageUrl.version.orEmpty()
        )
    }

    return sanitizedIdentifier(SBOM_PROJECT_TYPE, group.orEmpty(), name, version.orEmpty())
}

/**
 * Create an [Identifier] from the given parts, encoding the colons they may contain, such as in container image
 * digests (`sha256:...`) or Debian versions with an epoch (`1:2.4.47`), which ORT does not allow in identifiers. The
 * original values remain available in the package URL.
 */
internal fun sanitizedIdentifier(type: String, namespace: String, name: String, version: String): Identifier {
    fun String.encoded() = replace(":", "%3A")
    return Identifier(type.encoded(), namespace.encoded(), name.encoded(), version.encoded())
}

/**
 * Return the authors of this component, or, if the SBOM declares none, its supplier, such as the supplier,
 * manufacturer, or publisher of a CycloneDX component, so that the party responsible for the component is known.
 */
private fun SbomComponent.authorsOrSupplier(): Set<String> = authors.ifEmpty { setOfNotNull(supplier) }

/** Return the [VcsInfo] for the VCS URL of this component, which may contain a revision and a path. */
private fun SbomComponent.vcsInfo(): VcsInfo = vcsUrl?.let(::parseVcsUrl) ?: VcsInfo.EMPTY

/** Return the strongest verifiable hash among these hashes, or [Hash.NONE]. Invalid hash values are ignored. */
private fun List<SbomHash>.bestHash(): Hash =
    mapNotNull { hash ->
        HashAlgorithm.fromString(hash.algorithm).takeIf { it.isVerifiable }?.let { algorithm ->
            runCatching { Hash(hash.value, algorithm) }.getOrNull()
        }
    }.maxByOrNull { it.algorithm.size } ?: Hash.NONE
