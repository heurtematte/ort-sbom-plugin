# Getting started

## Requirements

The plugin is built against ORT 99, which requires **Java 25**.

!!! note "GitHub Packages"

    Until the artifacts are published to Maven Central, they are published to
    [GitHub Packages](https://github.com/heurtematte?tab=packages&repo_name=ort-sbom-plugin): `0.1.0-SNAPSHOT` from
    the `main` branch, and the version of each `v<version>` tag. GitHub Packages requires a token with the
    `read:packages` scope, also for public packages, for instance the token of the GitHub CLI (`gh auth token`) or the
    `GITHUB_TOKEN` of a GitHub Actions workflow.

    Alternatively, build the artifacts and publish them to your local Maven repository:

    ```shell
    git clone https://github.com/heurtematte/ort-sbom-plugin.git
    cd ort-sbom-plugin
    ./gradlew publishToMavenLocal
    ```

## Adding the plugin to an ORT-based application

Add the package manager to the runtime classpath of the application that runs the ORT Analyzer, such as a custom ORT
distribution (for ORT Server, see [Use with ORT Server](ort-server.md)):

=== "Gradle (Kotlin DSL)"

    ```kotlin
    repositories {
        maven("https://maven.pkg.github.com/heurtematte/ort-sbom-plugin") {
            credentials {
                username = providers.environmentVariable("GITHUB_ACTOR").getOrElse("token")
                password = providers.environmentVariable("GITHUB_TOKEN").orNull
            }

            content {
                includeGroup("org.eclipse.apoapsis.sbom")
            }
        }
    }

    dependencies {
        runtimeOnly("org.eclipse.apoapsis.sbom:sbom-package-manager:0.1.0-SNAPSHOT")
    }
    ```

=== "Maven"

    ```xml
    <repositories>
        <!-- The credentials are those of the server with the same id in settings.xml. -->
        <repository>
            <id>ort-sbom-plugin</id>
            <url>https://maven.pkg.github.com/heurtematte/ort-sbom-plugin</url>
            <snapshots><enabled>true</enabled></snapshots>
        </repository>
    </repositories>

    <dependency>
        <groupId>org.eclipse.apoapsis.sbom</groupId>
        <artifactId>sbom-package-manager</artifactId>
        <version>0.1.0-SNAPSHOT</version>
        <scope>runtime</scope>
    </dependency>
    ```

The plugin registers itself with ORT's `PackageManagerFactory` service, so ORT finds it on the classpath like its own
package managers.

## Enabling the plugin

ORT does not enable the plugin by default. Add `SBOM` to the enabled package managers of the analyzer:

=== "ORT configuration (config.yml)"

    ```yaml
    ort:
      analyzer:
        enabledPackageManagers:
          - SBOM
    ```

=== "Kotlin API"

    ```kotlin
    val config = AnalyzerConfiguration(enabledPackageManagers = listOf("SBOM"))
    val analyzer = Analyzer(config)

    val info = analyzer.findManagedFiles(directory, listOf(SbomFactory()))
    val ortResult = analyzer.analyze(info)
    ```

The analyzer then processes all files in the analyzed directory whose names match the
[definition file patterns](configuration.md), such as `bom.json`, `*.cdx.json`, or `*.spdx.json`, and whose content is
a supported SBOM. Other files matching the patterns are ignored. It also retrieves and analyzes the SBOMs listed in
[SBOM source files](sources.md) (`sbom-sources.yml`), for instance from Dependency-Track or sbomify.

!!! warning "SpdxDocumentFile"

    Do not enable the plugin together with ORT's `SpdxDocumentFile` package manager: both handle `*.spdx.json`,
    `*.spdx.yaml`, and `*.spdx.yml` files, so these SBOMs would be analyzed twice.

## Using the parser only

The `sbom-parser` library can also be used on its own, for instance to validate SBOMs or to inspect their content:

```kotlin
val document = SbomParser.parse(File("bom.cdx.json"))

println("${document.format.displayName} ${document.specVersion}")
document.roots.forEach { ref -> println("Describes ${document.components.getValue(ref).name}") }
document.components.values.forEach { component -> println("${component.name} ${component.version} ${component.purl}") }
document.warnings.forEach { warning -> println("Warning: $warning") }
```

`SbomParser.detectFormat(bytes)` only inspects the beginning of a document and returns its `SbomFormat`, or `null` if
it is not a supported SBOM. `SbomParser.parse` throws an `SbomParseException` with a descriptive message for documents
that are not supported or invalid.
