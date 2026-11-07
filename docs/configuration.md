# Configuration

The `SBOM` package manager has the following options:

| Option                         | Type        | Default    | Description                                                                                       |
| ------------------------------ | ----------- | ---------- | ------------------------------------------------------------------------------------------------- |
| `definitionFilePatterns`       | String list | see below  | File name patterns of the SBOMs to analyze. Matching files are analyzed if their content is a supported SBOM. |
| `attachUnreferencedComponents` | Boolean     | `true`     | Add components that are not reachable from a described component as direct dependencies of the project. If disabled, they are dropped with a warning. |
| `concludedLicenseHandling`     | Enum        | `DECLARED` | How licenses an SBOM marks as concluded are mapped, see below.                                     |

## Definition file patterns

By default, the following file names are recognized:

```text
*.cdx.json, *.cdx.xml, *.cyclonedx.json, *.cyclonedx.xml, *-cyclonedx.json, *-cyclonedx.xml,
bom.json, bom.xml, *.bom.json, *.bom.xml, sbom.json, sbom.xml, *.sbom.json, *.sbom.xml,
*.spdx.json, *.spdx.yaml, *.spdx.yml, *.spdx.xml, *.spdx, *.spdx3.json, *.spdx.jsonld
```

Files matching a pattern whose content is not a supported SBOM, such as a `bom.json` used for something else, are
ignored. ORT's usual path excludes and the directories it always ignores (such as `node_modules`) apply.

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
