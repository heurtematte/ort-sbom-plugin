# SBOM sources

Besides SBOM files, the `SBOM` package manager analyzes **SBOM source files**: YAML files that list where SBOMs are
published, such as a [Dependency-Track](https://dependencytrack.org/) instance, [sbomify](https://sbomify.com/), or any
URL. At each analysis, the package manager calls the API of each source, retrieves the current SBOM, and analyzes it
like an SBOM file. A Git repository that contains only a source file is therefore enough to analyze, in ORT or ORT Server,
SBOMs that are managed elsewhere.

## Source files

Source files are named `sbom-sources.yml` or `*.sbom-sources.yml` (or `.yaml`, see the
[`sourceFilePatterns` option](configuration.md)). They list the sources under the key `sources`, either as URLs or as
maps:

```yaml
sources:
  # A Dependency-Track project: the URL of its page in the Dependency-Track frontend.
  - https://sbom.eclipse.org/projects/00000000-0000-0000-0000-000000000000

  # The latest version of the same project, or a given version, with metadata missing from its SBOM.
  - url: https://sbom.eclipse.org/projects/00000000-0000-0000-0000-000000000000
    version: latest
    project:
      description: The product
      homepage: https://example.org/product
      licenses: [EPL-2.0]

  # A sbomify component (its latest SBOM, or the one of the given version) or product.
  - https://app.sbomify.com/component/<component-id>/
  - url: https://app.sbomify.com/public/product/eP_4dk8ixV/

  # Any SBOM document.
  - https://example.org/releases/1.0/bom.cdx.json

  # "type" overrides the type detected from the URL.
  - url: https://example.org/component/sbom/
    type: document
```

| Key       | Description                                                                                                         |
| --------- | ------------------------------------------------------------------------------------------------------------------- |
| `url`     | The URL of the source. Required.                                                                                    |
| `type`    | `dependency-track`, `sbomify`, or `document`. By default, detected from the URL: Dependency-Track project pages (`/projects/<uuid>`) and sbomify component and product pages (`/component/<id>/`, `/product/<id>/`, optionally below `/public`) are recognized, any other URL is a document. |
| `version` | For a Dependency-Track project, the version of the project with the same name to analyze, or `latest`: the version flagged as the latest version in Dependency-Track, or, if no version is flagged, the active version whose SBOM was imported last. For a sbomify component, the version of its SBOM, or `latest`. Not supported for documents and sbomify products. |
| `project` | Metadata of the projects described by the SBOM, see [Project metadata](#project-metadata). |

Each source becomes one or more projects, with the source file as definition file. Since the source file is versioned
in Git, the revision of an analysis records which sources, and which pinned versions, were analyzed.

## Project metadata

The metadata of a project, such as its description and licenses, is taken from the component that the SBOM describes.
SBOMs often lack it: the SBOMs exported by Dependency-Track, for instance, only contain the metadata of the project in
Dependency-Track. As the curations of ORT apply to packages, not to projects, the metadata of the projects of a source
can be given in the source file:

| Key           | Description                                                                         |
| ------------- | ----------------------------------------------------------------------------------- |
| `description` | The description of the project.                                                     |
| `homepage`    | The URL of the homepage of the project.                                             |
| `authors`     | The authors of the project, as a string or a list of strings.                       |
| `licenses`    | The declared licenses of the project, as SPDX expressions, as a string or a list.  |

Each given value replaces the corresponding value of the SBOM in all projects of the source; the other values are kept.
If the SBOM declares no authors, its supplier is used, such as the publisher of the project in Dependency-Track.

## Server identification

Before any request with credentials, the server of a Dependency-Track or sbomify source is identified through the
public endpoints these platforms provide, without credentials. If the server is not what the URL of the source suggests,
or cannot be reached, the source fails at once and no credentials are sent to it.

| Source           | Identification                                                                                              |
| ---------------- | ----------------------------------------------------------------------------------------------------------- |
| Dependency-Track | `GET <frontend>/static/config.json`: its `API_BASE_URL` gives the API server if the frontend does not serve the API; then `GET <api>/api/version`, whose `application` must be Dependency-Track. Both endpoints exist in Dependency-Track 4 and 5. |
| sbomify          | `GET <base>/api/v1/openapi.json`, whose title must be the sbomify API.                                     |
| Document         | None: a document is not a server.                                                                           |

Each server is identified once per analysis. Redirects are only followed on the same host. As the identification only
depends on these endpoints, upgrading Dependency-Track or sbomify does not change it, as long as the platforms keep
their API version 1.

## What is retrieved

| Source                  | API calls                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------ |
| Dependency-Track project | `GET /api/v1/project/{uuid}` on the identified API server, then `/api/v1/project/lookup` or `/api/v1/project/latest/{name}` if a version is selected (if no version is flagged as the latest version, `/api/v1/project?name={name}` to find the version imported last), then the CycloneDX inventory export `GET /api/v1/bom/cyclonedx/project/{uuid}?format=json&variant=inventory`. |
| sbomify component       | `GET /api/v1/components/{id}/sboms` (latest SBOM, or filtered by version), then `GET /api/v1/sboms/{id}/download`. |
| sbomify product         | `GET /api/v1/products/{id}/download?format=cyclonedx`, the aggregated SBOM of the product.                   |
| Document                | `GET` of the URL.                                                                                            |

Dependency-Track stores the components of uploaded SBOMs, not the documents themselves: the export is a CycloneDX SBOM
that Dependency-Track generates, whatever the format of the uploaded SBOM was. sbomify and documents are analyzed as
they are published, in any [supported format](formats.md).

## Credentials

Credentials are requested from the default authenticator of the JVM for the URL of the source:

- In **ORT Server**, it provides the credentials of the infrastructure service whose URL matches the source, for
  instance an infrastructure service with the URL `https://sbom.eclipse.org`. All infrastructure services of the
  organization, product, and repository are taken into account.
- With the **ORT CLI**, it reads the `.netrc` file, for instance
  `machine sbom.eclipse.org login api password <API key>`.

The password is used as follows:

| Source           | Usage                                                                                                 |
| ---------------- | ----------------------------------------------------------------------------------------------------- |
| Dependency-Track | API key, sent as `X-Api-Key`. See [Dependency-Track permissions](#dependency-track-permissions).      |
| sbomify          | Access token, sent as `Authorization: Bearer`. Public components and products do not need one.        |
| Document         | Basic authentication, with the user name.                                                            |

Dependency-Track requires an API key: without credentials, a Dependency-Track source fails at once, without any request.
sbomify components and products and documents are accessed anonymously without credentials. Credentials are only sent
to the origin of the source, or to the API server that the frontend of a Dependency-Track instance designates:
redirects to another host, port, or scheme are followed without credentials, and redirects from HTTPS to HTTP are
refused.

### Dependency-Track permissions

In Dependency-Track, API keys belong to a team (_Administration_ > _Access Management_ > _Teams_). The plugin only reads,
so the team needs a single permission:

| Permission       | Needed for                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------ |
| `VIEW_PORTFOLIO` | All requests: reading the project, looking up its versions, and exporting its SBOM.              |

If **portfolio access control** is enabled, the team also needs access to the projects to analyze, that is, to all
versions of a project when `version` is used: Dependency-Track answers `403` for the projects not assigned to the team.
Dependency-Track 5 also has the permission `PORTFOLIO_ACCESS_CONTROL_BYPASS`, which grants access to all projects.

Do not grant permissions such as `BOM_UPLOAD` or `PORTFOLIO_MANAGEMENT`: they allow modifying the portfolio and are
not needed. Status `401` means that the API key is missing or invalid, status `403` that the team lacks the
permission or access to the project; the error of the analysis explains both cases.

## Errors

If a source cannot be retrieved, for instance because of missing credentials or a version that does not exist, or if it
is not a supported SBOM, the analysis of the other sources continues. The failed source becomes a project named after
its URL with an error issue that explains the problem, such as:

```text
Could not retrieve the SBOM of Dependency-Track project 00000000-... at https://sbom.eclipse.org: Request to
'https://sbom.eclipse.org/api/v1/project/00000000-...' for Dependency-Track project ... failed with status 401. No
credentials are available for 'sbom.eclipse.org': in ORT Server, define an infrastructure service for this URL; with
the ORT CLI, add the host to the '.netrc' file.
```

A version that does not exist is reported as such, for instance "The Dependency-Track project 'che-server' has no
version 'main'".

An invalid source file, such as one with an unknown key or a version for a document, fails as a whole with an error.

## Using the library

The retrieval is implemented in the `sbom-sources` library, which can be used without ORT:

```kotlin
val entries = SbomSourceFile.parse(File("sbom-sources.yml"))
val fetcher = SbomFetcher(CredentialsProvider.DEFAULT)

entries.forEach { (source, project) ->
    val sbom = fetcher.fetch(source, outputDir)
    println("${source.description}: ${sbom.format.displayName} ${sbom.name} ${sbom.version} sha256:${sbom.sha256}")
}
```
