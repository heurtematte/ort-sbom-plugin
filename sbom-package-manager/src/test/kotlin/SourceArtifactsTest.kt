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

import com.github.packageurl.PackageURL

import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe

class SourceArtifactsTest : WordSpec({
    "sourceArtifactUrl()" should {
        "return the sources JAR of a Maven package in Maven Central" {
            PackageURL("pkg:maven/org.apache.commons/commons-lang3@3.8.1?type=jar").sourceArtifactUrl() shouldBe
                "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.8.1/" +
                "commons-lang3-3.8.1-sources.jar"
        }

        "use the repository of a Maven package" {
            PackageURL(
                "pkg:maven/org.eclipse.jgit/org.eclipse.jgit@7.4.0" +
                    "?repository_url=https://repo.eclipse.org/content/groups/releases/"
            ).sourceArtifactUrl() shouldBe "https://repo.eclipse.org/content/groups/releases/org/eclipse/jgit/" +
                "org.eclipse.jgit/7.4.0/org.eclipse.jgit-7.4.0-sources.jar"
        }

        "return no URL for Maven POMs and snapshots" {
            PackageURL("pkg:maven/org.eclipse.collections/eclipse-collections-parent@11.1.0?type=pom")
                .sourceArtifactUrl() should beNull()
            PackageURL("pkg:maven/org.example/lib@1.0-SNAPSHOT").sourceArtifactUrl() should beNull()
        }

        "return the tarball of an npm package" {
            PackageURL("pkg:npm/vite@7.1.5").sourceArtifactUrl() shouldBe
                "https://registry.npmjs.org/vite/-/vite-7.1.5.tgz"
        }

        "return the tarball of a scoped npm package" {
            PackageURL("pkg:npm/%40babel/core@7.28.4").sourceArtifactUrl() shouldBe
                "https://registry.npmjs.org/@babel/core/-/core-7.28.4.tgz"
        }

        "return the download URL of an npm package" {
            PackageURL(
                "pkg:npm/%40obeonetwork/react-trello@2.4.11?download_url=https%3A%2F%2Fnpm.pkg.github.com%2F" +
                    "download%2F%40ObeoNetwork%2Freact-trello%2F2.4.11%2F384ada405b80fc7105583b43f6aef05e1f26bf3b"
            ).sourceArtifactUrl() shouldBe "https://npm.pkg.github.com/download/@ObeoNetwork/react-trello/2.4.11/" +
                "384ada405b80fc7105583b43f6aef05e1f26bf3b"
        }

        "return no URL for other types or packages without version" {
            PackageURL("pkg:pypi/grpcio@1.83.0").sourceArtifactUrl() should beNull()
            PackageURL("pkg:npm/vite").sourceArtifactUrl() should beNull()
        }
    }
})
