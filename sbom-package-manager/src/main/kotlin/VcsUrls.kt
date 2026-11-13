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

import org.ossreviewtoolkit.downloader.VcsHost
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.VcsType
import org.ossreviewtoolkit.utils.ort.normalizeVcsUrl

/** A VCS URL in the format of Maven SCM, "scm:<provider>:<url>". */
private val SCM_URL_REGEX = Regex("scm:(?<provider>[^:@/]+):(?<url>.+)", RegexOption.IGNORE_CASE)

/** A VCS URL in the format of Maven SCM without provider, in the SCP-like Git syntax, such as "scm:git@host:path". */
private val SCM_SCP_URL_REGEX = Regex("scm:(?<user>[^:@/]+)@(?<host>[^:/]+)[:/](?<path>.+)", RegexOption.IGNORE_CASE)

/** The Maven SCM providers that ORT can download from. */
private val SCM_PROVIDERS = mapOf(
    "git" to VcsType.GIT,
    "svn" to VcsType.SUBVERSION,
    "hg" to VcsType.MERCURIAL
)

/** The parameters of a Maven SCM URL that Eclipse-SourceReferences, as written to SBOMs by Tycho, add to it. */
private const val PATH_PARAMETER = "path"
private const val TAG_PARAMETER = "tag"
private const val COMMIT_PARAMETER = "commitId"
private val SCM_PARAMETERS = setOf(PATH_PARAMETER, TAG_PARAMETER, COMMIT_PARAMETER)

/**
 * Return the [VcsInfo] for the given VCS [url] of a component, which may contain a revision and a path.
 *
 * Besides plain URLs, whose fragment denotes a path in the repository as in purls, this supports the format of Maven
 * SCM connections, "scm:<provider>:<url>", which SBOMs created from Maven or Tycho builds commonly use. Tycho adds the
 * values of the `Eclipse-SourceReferences` header of bundles as parameters, for instance
 * "scm:git:https://github.com/org/repo.git?path=bundles/a&tag=v1&commitId=0123abc", which give the path and the
 * revision; the commit is preferred over the tag. Providers that ORT does not support, such as CVS, are ignored.
 */
internal fun parseVcsUrl(url: String): VcsInfo {
    val trimmedUrl = url.trim()
    if (trimmedUrl.startsWith("scm:", ignoreCase = true)) return parseScmUrl(trimmedUrl)

    val path = trimmedUrl.substringAfter('#', "")
    return parseHostedUrl(trimmedUrl.substringBefore('#'), type = null).let { vcs ->
        if (path.isNotEmpty() && vcs.path.isEmpty()) vcs.copy(path = path) else vcs
    }
}

private fun parseScmUrl(url: String): VcsInfo {
    val (location, parameters) = splitScmParameters(url)

    val vcs = SCM_SCP_URL_REGEX.matchEntire(location)?.let { match ->
        val (user, host, path) = match.destructured

        // Like ORT for Maven projects, only accept the SCP-like syntax for Git.
        if (user != "git" && !host.startsWith("git")) return VcsInfo.EMPTY

        parseHostedUrl("https://$host/$path", VcsType.GIT)
    } ?: SCM_URL_REGEX.matchEntire(location)?.let { match ->
        val (provider, providerUrl) = match.destructured

        if (providerUrl.startsWith("//")) {
            // The provider is missing, as in "scm:https://github.com/org/repo", so detect the type from the URL.
            parseHostedUrl("$provider:$providerUrl", type = null)
        } else {
            val type = SCM_PROVIDERS[provider.lowercase()] ?: return VcsInfo.EMPTY
            parseHostedUrl(providerUrl, type)
        }
    } ?: return VcsInfo.EMPTY

    val tag = parameters[TAG_PARAMETER]?.takeUnless { it.isEmpty() || it == "HEAD" }
    val revision = parameters[COMMIT_PARAMETER]?.takeUnless { it.isEmpty() }
        ?: tag?.let { if (vcs.type == VcsType.SUBVERSION) "tags/$it" else it }

    return vcs.copy(
        revision = revision ?: vcs.revision,
        path = parameters[PATH_PARAMETER]?.trim('/')?.takeUnless { it.isEmpty() } ?: vcs.path
    )
}

/**
 * Parse the given [url] of a repository, using the conventions of known hosts such as GitHub to find the type, the
 * revision, and the path, and fall back to the given [type] of the SCM provider.
 *
 * SSH URLs of known hosts, such as "git@github.com:org/repo.git", are turned into HTTPS URLs: SBOMs often give them,
 * but the repositories they describe are mostly public, and the scanner of ORT Server has neither SSH keys nor SSH.
 */
private fun parseHostedUrl(url: String, type: VcsType?): VcsInfo {
    // Like ORT for Maven projects, remove the "git:" prefix that some connections repeat.
    val trimmedUrl = if (url.startsWith("git://")) url else url.removePrefix("git:")
    val vcs = VcsHost.parseUrl(normalizeVcsUrl(trimmedUrl).sshToHttps())

    return if (type != null && vcs.type == VcsType.UNKNOWN) vcs.copy(type = type) else vcs
}

/** An SSH URL as created by [normalizeVcsUrl], with an optional user and port. */
private val SSH_URL_REGEX = Regex("ssh://(?:[^@/]+@)?(?<host>[^:/]+)(?::\\d+)?/(?<path>.+)", RegexOption.IGNORE_CASE)

/** Return the HTTPS URL for this SSH URL if it belongs to a known host such as GitHub, or this URL otherwise. */
private fun String.sshToHttps(): String {
    val match = SSH_URL_REGEX.matchEntire(this) ?: return this
    val (host, path) = match.destructured
    return "https://$host/$path".takeIf { VcsHost.fromUrl(it) != null } ?: this
}

/**
 * Split the given Maven SCM [url] into its location and the parameters that Tycho adds from `Eclipse-SourceReferences`
 * after a "?" (or a ";" as in the header itself), separated by "&" (or ";"). Other query parameters, such as those of
 * Gitweb URLs ("?p=repo.git"), are part of the location.
 */
private fun splitScmParameters(url: String): Pair<String, Map<String, String>> {
    val index = url.indexOfAny(charArrayOf('?', ';'))
    if (index < 0) return url to emptyMap()

    val parameters = url.substring(index + 1).split('&', ';').mapNotNull { parameter ->
        val (key, value) = parameter.split('=', limit = 2).takeIf { it.size == 2 } ?: return@mapNotNull null
        key.trim() to value.trim().removeSurrounding("\"")
    }

    val (known, others) = parameters.partition { (key, _) -> key in SCM_PARAMETERS }
    if (known.isEmpty()) return url to emptyMap()

    val location = url.substring(0, index) +
        others.takeUnless { it.isEmpty() }?.joinToString("&", prefix = "?") { (key, value) -> "$key=$value" }.orEmpty()

    return location to known.toMap()
}
