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
import io.kotest.matchers.shouldBe

import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.VcsType

class VcsUrlsTest : WordSpec({
    "parseVcsUrl()" should {
        "parse a plain URL with a path in the fragment" {
            parseVcsUrl("https://github.com/org/repo.git#sub/dir") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/org/repo.git", "", "sub/dir")
        }

        "parse a Maven SCM connection with HTTPS" {
            parseVcsUrl("scm:git:https://gitbox.apache.org/repos/asf/commons-cli.git") shouldBe
                VcsInfo(VcsType.GIT, "https://gitbox.apache.org/repos/asf/commons-cli.git", "")
        }

        "parse a Maven SCM connection with the Git protocol" {
            parseVcsUrl("scm:git:git://github.com/junit-team/junit4.git") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/junit-team/junit4.git", "")
        }

        "parse a Maven SCM connection with SSH" {
            parseVcsUrl("scm:git:ssh://git@github.com/eclipse-ee4j/injection-api.git") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/eclipse-ee4j/injection-api.git", "")
        }

        "turn SSH URLs of known hosts into HTTPS URLs" {
            parseVcsUrl("git@github.com:org/repo.git") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/org/repo.git", "")
            parseVcsUrl("ssh://git@gitlab.com:2222/org/repo.git") shouldBe
                VcsInfo(VcsType.GIT, "https://gitlab.com/org/repo.git", "")
        }

        "keep SSH URLs of other hosts" {
            parseVcsUrl("scm:git:ssh://git@git.example.org/repo.git").url shouldBe "ssh://git@git.example.org/repo.git"
        }

        "parse a Maven SCM connection with the SCP-like syntax" {
            parseVcsUrl("scm:git:git@github.com:eclipse/lsp4j.git") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/eclipse/lsp4j.git", "")
        }

        "parse a Maven SCM connection without provider with the SCP-like syntax" {
            parseVcsUrl("scm:git@github.com:facebook/facebook-android-sdk.git") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/facebook/facebook-android-sdk.git", "")
        }

        "parse a Maven SCM connection to a Git server that is not a known host" {
            parseVcsUrl("scm:git:http://git.jcraft.com/jsch.git") shouldBe
                VcsInfo(VcsType.GIT, "http://git.jcraft.com/jsch.git", "")
        }

        "parse a Maven SCM connection to Subversion with a tag" {
            parseVcsUrl("scm:svn:http://svn.apache.org/repos/asf/commons/proper/collections?tag=v3") shouldBe
                VcsInfo(VcsType.SUBVERSION, "http://svn.apache.org/repos/asf/commons/proper/collections", "tags/v3")
        }

        "use the tag of a Maven SCM connection as revision, except HEAD" {
            parseVcsUrl("scm:git:https://github.com/bndtools/bnd.git?tag=7.4.0") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/bndtools/bnd.git", "7.4.0")
            parseVcsUrl("scm:git:https://github.com/bndtools/bnd.git?tag=HEAD") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/bndtools/bnd.git", "")
        }

        "prefer the commit to the tag of Eclipse-SourceReferences, and take the path" {
            parseVcsUrl(
                "scm:git:https://github.com/eclipse-platform/eclipse.platform.git" +
                    "?path=runtime/bundles/org.eclipse.core.runtime&tag=R4_38" +
                    "&commitId=0a81bf0425ca05de586eedbe2028949a112f1d55"
            ) shouldBe VcsInfo(
                VcsType.GIT,
                "https://github.com/eclipse-platform/eclipse.platform.git",
                "0a81bf0425ca05de586eedbe2028949a112f1d55",
                "runtime/bundles/org.eclipse.core.runtime"
            )
        }

        "accept the separators of the Eclipse-SourceReferences header" {
            parseVcsUrl("scm:git:https://github.com/eclipse/xtext.git;path=\"plugins/a\";tag=v2.30.0") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/eclipse/xtext.git", "v2.30.0", "plugins/a")
        }

        "keep other query parameters as part of the URL" {
            parseVcsUrl("scm:git:https://git.example.org/?p=repo.git") shouldBe
                VcsInfo(VcsType.GIT, "https://git.example.org/?p=repo.git", "")
        }

        "detect the type of a Maven SCM connection without provider" {
            parseVcsUrl("scm:https://github.com/org/repo.git") shouldBe
                VcsInfo(VcsType.GIT, "https://github.com/org/repo.git", "")
        }

        "ignore providers that ORT does not support" {
            parseVcsUrl("scm:cvs:pserver:anonymous@wsdl4j.cvs.sourceforge.net:/cvsroot/wsdl4j") shouldBe VcsInfo.EMPTY
        }

        "ignore local paths and values that are not URLs" {
            parseVcsUrl("@ObeoNetwork/react-trello") shouldBe VcsInfo.EMPTY
            parseVcsUrl("../repo") shouldBe VcsInfo.EMPTY
            parseVcsUrl("/srv/git/repo.git") shouldBe VcsInfo.EMPTY
            parseVcsUrl("file:///srv/git/repo.git") shouldBe VcsInfo.EMPTY
            parseVcsUrl("scm:git:file:///srv/git/repo.git") shouldBe VcsInfo.EMPTY
        }

        "expand the shortcuts of npm for known hosts" {
            parseVcsUrl("github:org/repo") shouldBe VcsInfo(VcsType.GIT, "https://github.com/org/repo.git", "")
            parseVcsUrl("gitlab:org/repo.git") shouldBe VcsInfo(VcsType.GIT, "https://gitlab.com/org/repo.git", "")
            parseVcsUrl("org/repo") shouldBe VcsInfo.EMPTY
        }
    }
})
