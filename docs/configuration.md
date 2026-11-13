# Configuration

The `SBOM` package manager has the following options:

| Option                         | Type        | Default    | Description                                                                                       |
| ------------------------------ | ----------- | ---------- | ------------------------------------------------------------------------------------------------- |
| `definitionFilePatterns`       | String list | see below  | File name patterns of the SBOMs to analyze. Matching files are analyzed if their content is a supported SBOM. |
| `sourceFilePatterns`           | String list | see below  | File name patterns of [SBOM source files](sources.md), which list SBOMs to retrieve from Dependency-Track, sbomify, or URLs. Empty to disable them. |
| `attachUnreferencedComponents` | Boolean     | `true`     | Add components that are not reachable from a described component as direct dependencies of the project. If disabled, they are dropped with a warning. |
| `includeFileComponents`        | Boolean     | `false`    | Create packages for files without package URL, such as the files of container images, which are ignored by default, see [mapping](mapping.md#files). |
| `concludedLicenseHandling`     | Enum        | `DECLARED` | How licenses an SBOM marks as concluded are mapped, see below.                                     |
| `deriveSourceArtifacts`        | Boolean     | `true`     | Give packages without source artifact in the SBOM the one derived from their package URL, see [mapping](mapping.md#source-artifacts). |
| `failFast`                     | Boolean     | `false`    | Stop retrieving the sources of a source file at the first failure, see [SBOM sources](sources.md#errors). |

## Definition file patterns

By default, the following file names are recognized:

```text
*.cdx.json, *.cdx.xml, *.cyclonedx.json, *.cyclonedx.xml, *-cyclonedx.json, *-cyclonedx.xml,
bom.json, bom.xml, *.bom.json, *.bom.xml, sbom.json, sbom.xml, *.sbom.json, *.sbom.xml,
*.spdx.json, *.spdx.yaml, *.spdx.yml, *.spdx.xml, *.spdx, *.spdx3.json, *.spdx.jsonld
```

Files matching a pattern whose content is not a supported SBOM, such as a `bom.json` used for something else, are
ignored. ORT's usual path excludes and the directories it always ignores (such as `node_modules`) apply.

## Source file patterns

By default, [SBOM source files](sources.md) are recognized by these names:

```text
sbom-sources.yml, sbom-sources.yaml, *.sbom-sources.yml, *.sbom-sources.yaml
```

Set the option to an empty string to ignore source files, for instance to make sure that an analysis does not access
the network.

## Concluded licenses

| Value       | Effect                                                                                                   |
| ----------- | -------------------------------------------------------------------------------------------------------- |
| `DECLARED`  | Use concluded licenses as declared licenses of packages that do not declare a license otherwise.          |
| `CONCLUDED` | Map them to the concluded license of the package, which takes precedence over declared licenses in ORT.   |
| `IGNORE`    | Drop them.                                                                                               |

Tools that generate SBOMs often put licenses they detected into the concluded license, for instance the GitHub
dependency graph. As the concluded license of ORT is meant for licenses a person concluded, `DECLARED` is the default.

## Setting options

=== "ORT configuration (config.yml)"

    ```yaml
    ort:
      analyzer:
        enabledPackageManagers:
          - SBOM
        packageManagers:
          SBOM:
            options:
              attachUnreferencedComponents: "false"
              concludedLicenseHandling: "CONCLUDED"
              definitionFilePatterns: "*.cdx.json,*.spdx.json"
    ```

=== "ORT Server run"

    ```json
    {
      "jobConfigs": {
        "analyzer": {
          "packageManagerOptions": {
            "SBOM": {
              "options": {
                "concludedLicenseHandling": "CONCLUDED"
              }
            }
          }
        }
      }
    }
    ```

=== "Kotlin API"

    ```kotlin
    val config = AnalyzerConfiguration(
        enabledPackageManagers = listOf("SBOM"),
        packageManagers = mapOf(
            "SBOM" to PackageManagerConfiguration(
                options = mapOf("concludedLicenseHandling" to "CONCLUDED")
            )
        )
    )
    ```
