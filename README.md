# ORT SBOM Plugin

[![Build](https://github.com/heurtematte/ort-sbom-plugin/actions/workflows/build.yml/badge.svg)](https://github.com/heurtematte/ort-sbom-plugin/actions/workflows/build.yml)
[![Documentation](https://github.com/heurtematte/ort-sbom-plugin/actions/workflows/docs.yml/badge.svg)](https://heurtematte.github.io/ort-sbom-plugin/)
[![License: EPL-2.0](https://img.shields.io/badge/License-EPL--2.0-blue.svg)](LICENSE)

**Documentation: <https://heurtematte.github.io/ort-sbom-plugin/>**

Ingest existing SBOMs into the [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort) (ORT), so that
advisors, the evaluator, and reporters can work on the components they list. Written for
[ORT Server](https://github.com/eclipse-apoapsis/ort-server) ([issue #2937](https://github.com/eclipse-apoapsis/ort-server/issues/2937)),
but usable with any ORT Analyzer.

| Module                 | Artifact                                             | Content                                                       |
| ---------------------- | ---------------------------------------------------- | ------------------------------------------------------------- |
| `sbom-parser`          | `org.eclipse.apoapsis.sbom:sbom-parser`              | Format detection and parsers into a format-independent model |
| `sbom-sources`         | `org.eclipse.apoapsis.sbom:sbom-sources`             | Source files and retrieval from Dependency-Track, sbomify, URLs |
| `sbom-package-manager` | `org.eclipse.apoapsis.sbom:sbom-package-manager`     | The `SBOM` package manager plugin for the ORT Analyzer        |

## Supported formats

The format and the specification version are detected from the content; they never need to be specified, as every
supported format identifies itself (`bomFormat`/`specVersion`, the XML namespace, `spdxVersion`, the JSON-LD context).

| Format    | Serializations             | Tested versions |
| --------- | -------------------------- | --------------- |
| CycloneDX | JSON, XML                  | 1.0 to 1.7      |
| SPDX      | JSON, YAML, tag-value, XML | 2.0 to 2.3      |
| SPDX      | JSON-LD                    | 3.0.0, 3.0.1    |

Documents may be encoded in UTF-8, UTF-16, or UTF-32. Other versions are accepted with a warning. SPDX RDF/XML and
CycloneDX Protocol Buffers are not supported.

## The `SBOM` package manager

The plugin is registered for ORT's `PackageManagerFactory` service with the ID `SBOM`. ORT does not enable it by
default; add it to `enabledPackageManagers` of the analyzer configuration. It then analyzes all files matching its
`definitionFilePatterns` (such as `*.cdx.json`, `bom.xml`, `*.spdx.json`) whose content is a supported SBOM, and the
SBOMs listed in source files (see below).
Do not enable it together with ORT's `SpdxDocumentFile` package manager, as both handle `*.spdx.json` files.

Mapping:

- Each component an SBOM describes (CycloneDX `metadata.component`, or the packages an SPDX document `DESCRIBES`)
  becomes a project of type `SBOM`; without such a component, a project named after the document is created.
- All other components become packages. Packages with a package URL get identifiers with the types of the ORT package
  managers (`Maven`, `NPM`, `PyPI`, ...), and keep their purl, so that advisors such as OSV, curations, and rules work.
- The dependency graph is preserved. Nested CycloneDX components and SPDX `CONTAINS` relationships are dependencies.
  Scopes come from the CycloneDX component scope or from the SPDX relationship type.
- The VCS declared for a described component is kept as its unprocessed VCS only, because ORT requires the processed
  VCS of a project to match the analyzed repository.

Options:

| Option                         | Default    | Description                                                                         |
| ------------------------------ | ---------- | ----------------------------------------------------------------------------------- |
| `definitionFilePatterns`       | see code   | File name patterns of SBOMs                                                         |
| `sourceFilePatterns`           | see code   | File name patterns of SBOM source files; empty to ignore them                       |
| `attachUnreferencedComponents` | `true`     | Add components not reachable in the dependency graph as direct project dependencies |
| `concludedLicenseHandling`     | `DECLARED` | Map concluded licenses as `DECLARED`, `CONCLUDED`, or `IGNORE`                      |
| `deriveSourceArtifacts`        | `true`     | Derive the source artifacts of Maven and npm packages from their package URL        |
| `failFast`                     | `false`    | Stop retrieving the sources of a source file at the first failure                   |

## SBOM sources

SBOM source files (`sbom-sources.yml`, `*.sbom-sources.yml`) list SBOMs published elsewhere. At each analysis, the
package manager retrieves them through the API of their source and analyzes them:

```yaml
sources:
  # A Dependency-Track project (URL of its page); "version" selects another version, or "latest".
  - url: https://sbom.eclipse.org/projects/00000000-0000-0000-0000-000000000000
    version: latest
  # A sbomify component or product.
  - https://app.sbomify.com/public/product/eP_4dk8ixV/
  # Any SBOM document.
  - https://example.org/releases/1.0/bom.cdx.json
```

Credentials come from the default authenticator: in ORT Server, the infrastructure service matching the URL (the
password is the Dependency-Track API key or the sbomify token); with the ORT CLI, the `.netrc` file. They are never sent
to another origin on redirects. A Dependency-Track API key only needs the permission `VIEW_PORTFOLIO` (and access to
the projects if portfolio access control is enabled). See the
[documentation](https://heurtematte.github.io/ort-sbom-plugin/sources/).

## ORT Server

The plugin can be added to the released images of ORT Server, without changing ORT Server: `ort-server/Dockerfile`
adds the jars to the core and analyzer worker images and appends them to their classpath. The
[ORT Server images](.github/workflows/ort-server-images.yml) workflow publishes them as
`ghcr.io/heurtematte/ort-sbom-plugin/ort-server-core:0.103.0` and
`ghcr.io/heurtematte/ort-sbom-plugin/ort-server-analyzer-worker:0.103.0`, together with copies of the other images of
the release, so that the Helm chart of ORT Server uses them all with:

```yaml
containerRegistry: ghcr.io/heurtematte/ort-sbom-plugin
```

To build the images yourself, run `ort-server/build-images.sh 0.103.0`. See
[Use with ORT Server](https://heurtematte.github.io/ort-sbom-plugin/ort-server/) for Docker Compose and the analysis of
SBOMs in ORT Server.

## Building

Requires Java 25, like ORT 99.

```shell
./gradlew build                 # compile and test
./gradlew publishToMavenLocal   # make the artifacts available to local builds, e.g. of ORT Server
./gradlew ortServerPlugin       # collect the jars to add to ORT Server images in build/ort-server-plugin
```

The version of ORT is set by the ORT version catalog in `settings.gradle.kts`.

Until they are on Maven Central, the artifacts are published to GitHub Packages
(`https://maven.pkg.github.com/heurtematte/ort-sbom-plugin`) by the `Build` workflow: the snapshot version from `main`,
and the version of each `v<version>` tag. Reading them requires a GitHub token with the `read:packages` scope, see
[Getting started](https://heurtematte.github.io/ort-sbom-plugin/getting-started/).

## Tests

The tests use real SBOMs from public sources as fixtures (`sbom-parser/src/testFixtures`), with the expected format and
specification version of each: SBOMs of Eclipse Foundation projects, examples of the CycloneDX specification (1.0 to
1.7) and of the SPDX tools (2.2, 2.3, UTF-16, XML), outputs of Syft, and exports of sbomify (CycloneDX 1.7, SPDX 3.0.1).
They are also published as the test fixtures of `sbom-parser` for the tests of consumers.

Two further tests parse and analyze every SBOM of a corpus, such as the one built by the `eclipse_sbom.py` script (from
sbom.eclipse.org, Maven Central, the GitHub dependency graph, the specification test suites, Kubernetes, and sbomify),
if `SBOM_CORPUS_DIR` points to it. The parser test fails if an SBOM is not detected or cannot be parsed and prints the
number of documents per format and version; the analysis test fails if the ORT Analyzer reports an error.

```shell
SBOM_CORPUS_DIR=../eclipse-sbom/sboms ./gradlew test --tests '*Corpus*' --rerun-tasks -i
```

With the public part of that corpus, 764 SBOMs are parsed and 761 analyzed without errors; only SPDX RDF/XML documents
are rejected.

## License

Copyright (c) 2026 Contributors to the Eclipse Foundation.

This program and the accompanying materials are made available under the terms of the
[Eclipse Public License 2.0](LICENSE) (`SPDX-License-Identifier: EPL-2.0`). See [NOTICE.md](NOTICE.md) for the
third-party content; the SBOMs used as test fixtures are documents published by third parties, listed in
[SOURCES.md](sbom-parser/src/testFixtures/resources/sboms/SOURCES.md).
