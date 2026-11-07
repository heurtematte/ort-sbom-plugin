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

import java.io.File

/**
 * Access to SBOM test fixtures. The fixtures are real SBOMs from public sources (collected with the `eclipse_sbom.py`
 * script): SBOMs published by Eclipse Foundation projects, examples of the CycloneDX and SPDX specifications and tools,
 * and outputs of generators and SBOM platforms. Together, they cover all supported formats and specification versions.
 */
object SbomFixtures {
    /** A CycloneDX 1.4 JSON SBOM with a root component, four dependencies, and a dependency graph. */
    const val CYCLONEDX_1_4_JSON = "cyclonedx/angus-imap-2.0.3-v1.4.cdx.json"

    /** The XML serialization of [CYCLONEDX_1_4_JSON]. */
    const val CYCLONEDX_1_4_XML = "cyclonedx/angus-imap-2.0.3-v1.4.cdx.xml"

    /** A CycloneDX 1.4 JSON SBOM that only describes its root component. */
    const val CYCLONEDX_1_4_ROOT_ONLY = "cyclonedx/krazo-documentation-4.0.0-v1.4.cdx.json"

    /** An excerpt of a CycloneDX 1.5 JSON SBOM, whose dependency graph does not reach all components. */
    const val CYCLONEDX_1_5_JSON_EXCERPT = "cyclonedx/jetty-home-12.0.21-excerpt-v1.5.cdx.json"

    /** A CycloneDX 1.6 JSON SBOM with a deep dependency graph. */
    const val CYCLONEDX_1_6_JSON = "cyclonedx/vertx-grpcio-common-5.0.0.CR7-v1.6.cdx.json"

    /** The XML serialization of [CYCLONEDX_1_6_JSON]. */
    const val CYCLONEDX_1_6_XML = "cyclonedx/vertx-grpcio-common-5.0.0.CR7-v1.6.cdx.xml"

    /** A flat CycloneDX 1.6 JSON SBOM without dependency graph whose components have no purls. */
    const val CYCLONEDX_1_6_FLAT = "cyclonedx/temurin-jdk-21.0.13-v1.6.cdx.json"

    /** The example BOM of the CycloneDX 1.0 specification (XML only), without root component. */
    const val CYCLONEDX_1_0_XML = "cyclonedx/cyclonedx-spec-valid-bom-v1.0.cdx.xml"

    /** The example BOM of the CycloneDX 1.1 specification (XML only), with nested components. */
    const val CYCLONEDX_1_1_XML = "cyclonedx/cyclonedx-spec-valid-bom-v1.1.cdx.xml"

    /** The dependency example of the CycloneDX 1.2 specification. */
    const val CYCLONEDX_1_2_JSON = "cyclonedx/cyclonedx-spec-valid-dependency-v1.2.cdx.json"

    /** The example BOM of the CycloneDX 1.3 specification. */
    const val CYCLONEDX_1_3_JSON = "cyclonedx/cyclonedx-spec-valid-bom-v1.3.cdx.json"

    /** The example BOM of the CycloneDX 1.7 specification. */
    const val CYCLONEDX_1_7_JSON = "cyclonedx/cyclonedx-spec-valid-bom-v1.7.cdx.json"

    /** The XML serialization of [CYCLONEDX_1_7_JSON]. */
    const val CYCLONEDX_1_7_XML = "cyclonedx/cyclonedx-spec-valid-bom-v1.7.cdx.xml"

    /** A CycloneDX 1.7 SBOM written by Syft whose timestamp and serial number are not valid. */
    const val CYCLONEDX_1_7_INVALID_METADATA = "cyclonedx/syft-redacted-metadata-v1.7.cdx.json"

    /** A CycloneDX 1.7 SBOM written by Syft with Debian packages whose versions have an epoch (`1:2.4.47`). */
    const val CYCLONEDX_1_7_DEBIAN = "cyclonedx/syft-debian-epoch-v1.7.cdx.json"

    /** A CycloneDX 1.7 SBOM of a product exported by sbomify. */
    const val CYCLONEDX_1_7_SBOMIFY = "cyclonedx/sbomify-product-v1.7.cdx.json"

    /** An SPDX 2.3 JSON SBOM produced by the GitHub dependency graph. */
    const val SPDX_2_3_JSON = "spdx/p2repo-sbom-v2.3.spdx.json"

    /** The YAML serialization of [SPDX_2_3_JSON]. */
    const val SPDX_2_3_YAML = "spdx/p2repo-sbom-v2.3.spdx.yaml"

    /** The tag-value serialization of [SPDX_2_3_JSON]. */
    const val SPDX_2_3_TAG_VALUE = "spdx/p2repo-sbom-v2.3.spdx"

    /** The SPDX 3.0.1 JSON-LD conversion of [SPDX_2_3_JSON]. */
    const val SPDX_3_0_JSON_LD = "spdx/p2repo-sbom-v3.0.1.spdx3.json"

    /** The SPDX 2.2 example document of the SPDX tools in JSON, encoded in UTF-16. */
    const val SPDX_2_2_JSON_UTF16 = "spdx/spdx-tools-example-utf16-v2.2.spdx.json"

    /** The SPDX 2.2 example document of the SPDX tools in tag-value, encoded in UTF-16. */
    const val SPDX_2_2_TAG_VALUE_UTF16 = "spdx/spdx-tools-example-utf16-v2.2.spdx"

    /** The SPDX 2.3 example document of the SPDX tools in XML. */
    const val SPDX_2_3_XML = "spdx/spdx-tools-example-v2.3.spdx.xml"

    /** The SPDX 2.2 example document of the SPDX tools in tag-value. */
    const val SPDX_2_2_TAG_VALUE = "spdx/spdx-tools-example-v2.2.spdx"

    /** The SPDX 2.2 example document of the SPDX tools in YAML. */
    const val SPDX_2_2_YAML = "spdx/spdx-tools-example-v2.2.spdx.yaml"

    /** An SPDX 3.0.1 document of a product exported by sbomify, with several described components. */
    const val SPDX_3_0_SBOMIFY = "spdx/sbomify-product-v3.0.1.spdx3.json"

    /** An SPDX 3.0.0 example that consists of a single package element instead of a graph. */
    const val SPDX_3_0_SINGLE_ELEMENT = "spdx/spdx-3-model-single-package-v3.0.0.spdx3.json"

    /** All fixtures associated with their expected format and specification version. */
    val ALL = mapOf(
        CYCLONEDX_1_0_XML to (SbomFormat.CYCLONEDX_XML to "1.0"),
        CYCLONEDX_1_1_XML to (SbomFormat.CYCLONEDX_XML to "1.1"),
        CYCLONEDX_1_2_JSON to (SbomFormat.CYCLONEDX_JSON to "1.2"),
        CYCLONEDX_1_3_JSON to (SbomFormat.CYCLONEDX_JSON to "1.3"),
        CYCLONEDX_1_4_JSON to (SbomFormat.CYCLONEDX_JSON to "1.4"),
        CYCLONEDX_1_4_XML to (SbomFormat.CYCLONEDX_XML to "1.4"),
        CYCLONEDX_1_4_ROOT_ONLY to (SbomFormat.CYCLONEDX_JSON to "1.4"),
        CYCLONEDX_1_5_JSON_EXCERPT to (SbomFormat.CYCLONEDX_JSON to "1.5"),
        CYCLONEDX_1_6_JSON to (SbomFormat.CYCLONEDX_JSON to "1.6"),
        CYCLONEDX_1_6_XML to (SbomFormat.CYCLONEDX_XML to "1.6"),
        CYCLONEDX_1_6_FLAT to (SbomFormat.CYCLONEDX_JSON to "1.6"),
        CYCLONEDX_1_7_JSON to (SbomFormat.CYCLONEDX_JSON to "1.7"),
        CYCLONEDX_1_7_XML to (SbomFormat.CYCLONEDX_XML to "1.7"),
        CYCLONEDX_1_7_INVALID_METADATA to (SbomFormat.CYCLONEDX_JSON to "1.7"),
        CYCLONEDX_1_7_DEBIAN to (SbomFormat.CYCLONEDX_JSON to "1.7"),
        CYCLONEDX_1_7_SBOMIFY to (SbomFormat.CYCLONEDX_JSON to "1.7"),
        SPDX_2_2_TAG_VALUE to (SbomFormat.SPDX_TAG_VALUE to "SPDX-2.2"),
        SPDX_2_2_YAML to (SbomFormat.SPDX_YAML to "SPDX-2.2"),
        SPDX_2_3_JSON to (SbomFormat.SPDX_JSON to "SPDX-2.3"),
        SPDX_2_3_YAML to (SbomFormat.SPDX_YAML to "SPDX-2.3"),
        SPDX_2_3_TAG_VALUE to (SbomFormat.SPDX_TAG_VALUE to "SPDX-2.3"),
        SPDX_2_2_JSON_UTF16 to (SbomFormat.SPDX_JSON to "SPDX-2.2"),
        SPDX_2_2_TAG_VALUE_UTF16 to (SbomFormat.SPDX_TAG_VALUE to "SPDX-2.2"),
        SPDX_2_3_XML to (SbomFormat.SPDX_XML to "SPDX-2.3"),
        SPDX_3_0_JSON_LD to (SbomFormat.SPDX3_JSON_LD to "SPDX-3.0.1"),
        SPDX_3_0_SBOMIFY to (SbomFormat.SPDX3_JSON_LD to "SPDX-3.0.1"),
        SPDX_3_0_SINGLE_ELEMENT to (SbomFormat.SPDX3_JSON_LD to "SPDX-3.0.0")
    )

    /** Return the content of the fixture with the given [path]. */
    fun bytes(path: String): ByteArray =
        checkNotNull(SbomFixtures::class.java.getResourceAsStream("/sboms/$path")) {
            "Missing SBOM fixture '$path'."
        }.use { it.readBytes() }

    /** Copy the fixture with the given [path] into the given [directory] and return the created file. */
    fun copyTo(directory: File, path: String, fileName: String = path.substringAfterLast('/')): File =
        directory.resolve(fileName).apply { writeBytes(bytes(path)) }
}
