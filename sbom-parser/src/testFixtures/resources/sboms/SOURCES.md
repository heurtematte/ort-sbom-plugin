# Sources of the SBOM fixtures

The fixtures are unmodified documents from public sources, unless noted otherwise.

| Fixture                                                  | Source                                                                                         | License          |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------- |
| `cyclonedx/angus-imap-2.0.3-v1.4.cdx.{json,xml}`         | Maven Central, `org.eclipse.angus:imap:2.0.3`, classifier `cyclonedx`                          | Project's (EPL-2.0 / GPL-2.0 with Classpath exception / BSD-3-Clause) |
| `cyclonedx/krazo-documentation-4.0.0-v1.4.cdx.json`      | Maven Central, `org.eclipse.krazo:krazo-documentation:4.0.0`, classifier `cyclonedx`           | Project's (EPL-2.0) |
| `cyclonedx/jetty-home-12.0.21-excerpt-v1.5.cdx.json`     | Maven Central, `org.eclipse.jetty:jetty-home:12.0.21`; reduced to 25 components                | Project's (EPL-2.0 / Apache-2.0) |
| `cyclonedx/vertx-grpcio-common-5.0.0.CR7-v1.6.cdx.*`     | Maven Central, `io.vertx:vertx-grpcio-common:5.0.0.CR7`, classifier `cyclonedx`                | Project's (EPL-2.0 / Apache-2.0) |
| `cyclonedx/temurin-jdk-21.0.13-v1.6.cdx.json`            | Eclipse Temurin release `jdk-21.0.13+9`, SBOM asset                                            | Project's (GPL-2.0 with Classpath exception) |
| `cyclonedx/cyclonedx-spec-valid-*.cdx.*`                 | github.com/CycloneDX/specification, `tools/src/test/resources`                                 | Apache-2.0       |
| `cyclonedx/syft-*-v1.7.cdx.json`                         | github.com/anchore/syft, `syft/format/cyclonedxjson/testdata/snapshot`                         | Apache-2.0       |
| `cyclonedx/sbomify-product-v1.7.cdx.json`                | app.sbomify.com, public product `eP_4dk8ixV`, CycloneDX 1.7 export                             | Public SBOM      |
| `spdx/p2repo-sbom-v2.3.spdx.json`                        | GitHub dependency graph of `eclipse-cbi/p2repo-sbom`                                           | CC0-1.0 (SPDX data license) |
| `spdx/p2repo-sbom-v2.3.spdx`, `.spdx.yaml`, `v3.0.1`     | Converted from the previous file with `eclipse_sbom.py variants`                               | CC0-1.0          |
| `spdx/spdx-tools-example-*`                              | github.com/spdx/tools-python, `tests/spdx/data`                                                | Apache-2.0       |
| `spdx/spdx-3-model-single-package-v3.0.0.spdx3.json`     | github.com/spdx/spdx-3-model, `serialization/jsonld/examples/package1.json`                    | Community Specification License 1.0 |
| `spdx/sbomify-product-v3.0.1.spdx3.json`                 | app.sbomify.com, public product `eP_4dk8ixV`, SPDX 3.0 export                                  | CC0-1.0 (SPDX data license) |
