# Architecture

This page describes the architecture of the plugin with the [C4 model](https://c4model.com/), from the systems it
interacts with down to its components, using ORT Server as the host application. The plugin works the same way in any
application that runs the ORT Analyzer, such as the ORT CLI.

## System context

ORT Server analyzes the SBOMs that are committed to Git repositories or listed in [source files](sources.md), and
retrieves the latter from Dependency-Track, sbomify, or any web server. The packages of the SBOMs are then checked like
those of source code, for instance for vulnerabilities.

```mermaid
C4Context
    title System context of the SBOM ingestion

    Person(team, "Compliance or security team", "Reviews the licenses and vulnerabilities of products")
    Person(producer, "SBOM producer", "Build pipeline, vendor, or project team")

    System(ortServer, "ORT Server with the SBOM plugin", "Analyzes repositories and SBOMs, runs advisors, rules, and reporters")

    System_Ext(git, "Git hosting", "SBOM files and sbom-sources.yml")
    System_Ext(dt, "Dependency-Track", "Portfolio of SBOMs, such as sbom.eclipse.org")
    System_Ext(sbomify, "sbomify", "SBOMs of components and products")
    System_Ext(web, "Web servers", "SBOM documents, such as release assets")
    System_Ext(advisors, "Vulnerability databases", "OSV and other advisors")

    Rel(team, ortServer, "Starts runs, reviews results", "UI, REST API")
    Rel(producer, git, "Commits SBOMs and source files")
    Rel(producer, dt, "Uploads SBOMs")
    Rel(producer, sbomify, "Uploads SBOMs")
    Rel(ortServer, git, "Clones", "Git")
    Rel(ortServer, dt, "Exports SBOMs", "REST, API key")
    Rel(ortServer, sbomify, "Downloads SBOMs", "REST, token")
    Rel(ortServer, web, "Downloads SBOMs", "HTTPS")
    Rel(ortServer, advisors, "Queries vulnerabilities", "HTTPS")

    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

## Containers

Within ORT Server, two containers include the plugin: the **core**, whose plugin manager lists the installed plugins and
rejects runs that enable unknown package managers, and the **analyzer worker**, which runs the ORT Analyzer with the
`SBOM` package manager. The other containers are unchanged: they work on the projects and packages the analyzer
produced.

```mermaid
C4Container
    title Containers of ORT Server with the SBOM plugin

    Person(team, "Compliance or security team")

    System_Boundary(ortServer, "ORT Server") {
        Container(ui, "UI", "React", "Repositories, runs, results")
        Container(core, "Core", "Kotlin, Ktor, plugin", "REST API, plugin manager, validation of runs")
        Container(orchestrator, "Orchestrator", "Kotlin", "Schedules the jobs of runs")
        Container(analyzer, "Analyzer worker", "Kotlin, ORT Analyzer, plugin", "Clones the repository, runs the package managers")
        Container(workers, "Other workers", "Kotlin, ORT", "Advisor, evaluator, reporter, notifier")
        ContainerDb(db, "Database", "PostgreSQL", "Runs, results, infrastructure services")
        ContainerDb(secrets, "Secret storage", "Vault or file", "Credentials of infrastructure services")
    }

    System_Ext(git, "Git hosting")
    System_Ext(sources, "Dependency-Track, sbomify, web servers")

    Rel(team, ui, "Uses", "HTTPS")
    Rel(ui, core, "Calls", "REST")
    Rel(core, orchestrator, "Run created", "Message queue")
    Rel(orchestrator, analyzer, "Analyzer job", "Kubernetes job or queue")
    Rel(orchestrator, workers, "Later jobs")
    Rel(analyzer, git, "Clones", "Git")
    Rel(analyzer, sources, "Retrieves SBOMs", "REST, HTTPS")
    Rel(analyzer, secrets, "Resolves credentials")
    Rel(analyzer, db, "Stores projects and packages")
    Rel(workers, db, "Read results")

    UpdateElementStyle(core, $bgColor="#1a6b3c", $borderColor="#0f4426")
    UpdateElementStyle(analyzer, $bgColor="#1a6b3c", $borderColor="#0f4426")
    UpdateLayoutConfig($c4ShapeInRow="4", $c4BoundaryInRow="1")
```

## Components

The plugin consists of three libraries. `sbom-package-manager` is the ORT plugin; it uses `sbom-sources` to retrieve
remote SBOMs and `sbom-parser` to read all SBOMs into a format-independent model, which it maps to the ORT model.
Credentials are requested from the default `java.net.Authenticator`, which ORT Server backs with its infrastructure
services, so the plugin does not depend on ORT Server.

```mermaid
C4Component
    title Components of the plugin in the analyzer worker

    Container(ortAnalyzer, "ORT Analyzer", "ORT 99", "Finds definition files, runs package managers")
    Container(authenticator, "Authenticator", "java.net.Authenticator", "ORT Server: infrastructure services; ORT CLI: .netrc")

    Container_Boundary(pm, "sbom-package-manager") {
        Component(sbom, "Sbom", "PackageManager plugin", "Selects SBOM and source files, converts documents into projects")
        Component(handler, "SbomDependencyHandler", "DependencyHandler", "Packages and identifiers from purls, dependency graph")
    }

    Container_Boundary(src, "sbom-sources") {
        Component(sourceFile, "SbomSourceFile", "kaml", "Parses sbom-sources.yml into sources")
        Component(fetcher, "SbomFetcher", "java.net.http", "Calls the APIs, keeps credentials on the origin")
    }

    Container_Boundary(parser, "sbom-parser") {
        Component(sbomParser, "SbomParser", "Kotlin", "Detects format and version, decodes UTF-8/16/32")
        Component(cdx, "CycloneDxParser", "cyclonedx-core-java", "CycloneDX 1.0 to 1.7, JSON and XML")
        Component(spdx2, "Spdx2Parser", "kotlinx-serialization, kaml, DOM", "SPDX 2.x, JSON, YAML, tag-value, XML")
        Component(spdx3, "Spdx3Parser", "kotlinx-serialization", "SPDX 3.0, JSON-LD")
    }

    System_Ext(remote, "Dependency-Track, sbomify, web servers")

    Rel(ortAnalyzer, sbom, "Definition files")
    Rel(sbom, sourceFile, "Source files")
    Rel(sbom, fetcher, "Sources")
    Rel(fetcher, authenticator, "Credentials for URL")
    Rel(fetcher, remote, "GET", "HTTPS")
    Rel(sbom, sbomParser, "SBOM files and retrieved SBOMs")
    Rel(sbomParser, cdx, "CycloneDX")
    Rel(sbomParser, spdx2, "SPDX 2")
    Rel(sbomParser, spdx3, "SPDX 3")
    Rel(sbom, handler, "SbomDocument")

    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="2")
```

## Dynamic view: analyzing a source file

The following steps happen in the analyzer worker for a repository that contains an `sbom-sources.yml` file listing a
Dependency-Track project.

```mermaid
C4Dynamic
    title Analysis of a source file with a Dependency-Track project

    Container(ortAnalyzer, "ORT Analyzer", "ORT 99")
    Container_Boundary(plugin, "SBOM plugin") {
        Component(sbom, "Sbom", "sbom-package-manager")
        Component(sourceFile, "SbomSourceFile", "sbom-sources")
        Component(fetcher, "SbomFetcher", "sbom-sources")
        Component(sbomParser, "SbomParser", "sbom-parser")
        Component(handler, "SbomDependencyHandler", "sbom-package-manager")
    }
    Container(authenticator, "OrtServerAuthenticator", "ORT Server")
    System_Ext(dt, "Dependency-Track")

    Rel(ortAnalyzer, sbom, "resolveDependencies(sbom-sources.yml)")
    Rel(sbom, sourceFile, "parse")
    Rel(sbom, fetcher, "fetch(source)")
    Rel(fetcher, authenticator, "Credentials for the API URL")
    Rel(fetcher, dt, "Project, version lookup, CycloneDX export", "X-Api-Key")
    Rel(sbom, sbomParser, "parse(retrieved SBOM)")
    Rel(sbom, handler, "Projects, packages, graph")
    Rel(sbom, ortAnalyzer, "PackageManagerResult")

    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

## Deployment

Without changing ORT Server, the plugin is deployed with images derived from the released images of ORT Server. The
[ORT Server images workflow](ort-server.md#published-images) adds the jars of the plugin to the core and analyzer worker
images, checks that they contain the ORT version the plugin was built for, and copies the other images, so that the
Helm chart of ORT Server uses them with a single `containerRegistry` value. In the analyzer pod, only the analysis
container runs the plugin; it receives the credentials of the infrastructure services from the preparation container.

```mermaid
C4Deployment
    title Deployment of ORT Server with the SBOM plugin

    Deployment_Node(github, "GitHub", "heurtematte/ort-sbom-plugin") {
        Container(workflow, "ORT Server images workflow", "GitHub Actions, Docker", "Base image + plugin jars, ORT version check")
        ContainerDb(registry, "ghcr.io/heurtematte/ort-sbom-plugin", "Container registry", "ort-server-core, ort-server-analyzer-worker, copies of the other images")
    }

    Deployment_Node(k8s, "Kubernetes cluster", "Helm chart of ORT Server") {
        Deployment_Node(corePod, "Core pod", "ort-server-core") {
            Container(core, "Core", "JVM", "/app/libs/* + /app/plugins/*")
        }
        Deployment_Node(analyzerPod, "Analyzer job pod", "ort-server-analyzer-worker") {
            Container(prep, "analyzerinit", "Preparation phase", "Clones, resolves credentials")
            Container(main, "analyzer-main", "Analysis phase", "ORT Analyzer with the SBOM plugin")
            Container(result, "analyzerresult", "Result phase", "Stores the results")
        }
    }

    Rel(workflow, registry, "Pushes")
    Rel(corePod, registry, "Pulls")
    Rel(analyzerPod, registry, "Pulls")
    Rel(prep, main, "Repository, auth-info.json", "emptyDir")
    Rel(main, result, "Analyzer result", "emptyDir")

    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="2")
```

## Design decisions

| Decision | Rationale |
| -------- | --------- |
| An ORT package manager plugin | ORT discovers package managers with the `ServiceLoader`, so the plugin works in ORT and ORT Server without changing them, and all later steps of ORT apply to SBOMs as to source code. |
| Format and version detected from the content | Every supported format identifies itself, so users never have to specify it, and files with unusual names are recognized. |
| A format-independent model | The six serializations of CycloneDX and SPDX are read into one `SbomDocument`, which is mapped to ORT once. |
| Identifiers derived from purls | Packages get the identifiers of ORT's native package managers (`Maven`, `NPM`, ...), so advisors, curations, and rules work on them. |
| The `DependencyGraphBuilder` of ORT | Packages shared by many projects are stored once, which keeps large SBOMs, such as those of Kubernetes, small in the result. |
| Remote sources retrieved at each analysis | The results follow the SBOMs maintained in Dependency-Track or sbomify, while the source file, versioned in Git, records what is analyzed. |
| Credentials from the default authenticator | No dependency on ORT Server: its infrastructure services, or the `.netrc` file of the ORT CLI, provide the credentials. |
| Credentials only for the origin of a source | Redirects to other origins are followed anonymously, and redirects from HTTPS to HTTP are refused, so that API keys cannot leak. |
| Images derived from released images | The plugin can be used before it is part of ORT Server; the build fails if the image uses another ORT version, as plugins must be built for the ORT version of the host. |
