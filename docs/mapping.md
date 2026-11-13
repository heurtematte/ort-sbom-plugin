# How SBOMs are mapped

The parser converts every supported format into a format-independent model, which the package manager maps to the ORT
model. This page describes the mapping.

## Projects

Each component that the SBOM **describes** becomes an ORT project of type `SBOM`:

- in CycloneDX, the component in `metadata.component`;
- in SPDX 2, the packages listed in `documentDescribes` or targeted by a `DESCRIBES` relationship of the document;
- in SPDX 3, the root elements of the `SpdxDocument`, resolving nested collections such as a `software_Sbom`.

If an SBOM describes no component, a project named after the document (or the file) is created. If several described
components have the same coordinates, for instance the same artifact for different architectures, their names are
qualified with their reference in the document, as ORT requires unique project identifiers.

The VCS declared for a described component is kept as the unprocessed VCS of the project only, because ORT requires the
processed VCS of a project to match the analyzed repository.

## Packages

All other components become packages.

| ORT property          | CycloneDX                                    | SPDX 2                                  | SPDX 3                                   |
| --------------------- | -------------------------------------------- | --------------------------------------- | ---------------------------------------- |
| Identifier, purl      | `purl`, else `group`, `name`, `version`      | `purl` external reference, else name    | `software_packageUrl` / identifier       |
| CPE                   | `cpe`                                        | `cpe23Type` / `cpe22Type` reference     | `cpe23` / `cpe22` identifier             |
| Declared licenses     | `licenses` (declared)                        | `licenseDeclared`                       | `hasDeclaredLicense` relationships       |
| Concluded license     | `licenses` (acknowledgement `concluded`)     | `licenseConcluded`                      | `hasConcludedLicense` relationships      |
| Authors               | `authors`, `author`, else `supplier`, `manufacturer`, `publisher` | `originator`, else `supplier` | `originatedBy`, else `suppliedBy` |
| Description           | `description`                                | `description`, `summary`                | `description`, `summary`                 |
| Homepage              | `website` external reference                 | `homepage`                              | `software_homePage`                      |
| VCS                   | `vcs` external reference                     | VCS `downloadLocation`                  | `vcs` external reference                 |
| Binary artifact       | `distribution` external reference + hash     | –                                       | –                                        |
| Source artifact       | `source-distribution` external reference     | `downloadLocation` + checksum           | `software_downloadLocation`              |

### Identifiers

Packages with a package URL get identifiers derived from it, with the types used by the package managers of ORT, for
instance `Maven`, `NPM`, `PyPI`, `Go`, `Crate`, `NuGet`, `Gem`, `Composer`, `Pod`, or `Pub`. Other purl types, such as
`deb`, `rpm`, `apk`, `oci`, or `generic`, are kept as they are. The original purl is stored in the package, so that
advisors such as OSV query the exact package.

ORT does not allow colons in the parts of identifiers, but they are common in SBOMs, for instance in container image
digests (`sha256:...`) or in Debian versions with an epoch (`1:2.4.47`). They are encoded as `%3A`; the purl keeps the
original value.

Components without a package URL get identifiers of type `SBOM`.

### VCS

VCS URLs can also have the format of Maven SCM connections, `scm:<provider>:<url>`, which SBOMs created from Maven
and Tycho builds commonly use, for instance `scm:git:git@github.com:eclipse/lsp4j.git` or
`scm:svn:http://svn.apache.org/repos/asf/commons/proper/collections`. For bundles, Tycho adds the values of their
`Eclipse-SourceReferences` header as parameters, as in
`scm:git:https://github.com/org/repo.git?path=bundles/a&tag=v1&commitId=0123abc`: they give the path in the repository
and the revision, the commit being preferred over the tag. Providers that ORT cannot download from, such as CVS, are
ignored.

SSH URLs of known hosts, such as GitHub, GitLab, or Bitbucket, are turned into HTTPS URLs, as the repositories that
SBOMs describe are mostly public and scanners usually have no SSH keys.

### Licenses

Licenses that an SBOM marks as concluded are handled according to the `concludedLicenseHandling` option (see
[configuration](configuration.md)). By default, they are used as declared licenses of packages that do not declare a
license otherwise, because tools often put detected licenses there.

## Dependency graph

The dependency graph of the SBOM is preserved:

- CycloneDX: the `dependencies` section and nested `components`.
- SPDX 2: the relationships `DEPENDS_ON`, `DEPENDENCY_OF`, `CONTAINS`, `CONTAINED_BY`, `DYNAMIC_LINK`, `STATIC_LINK`,
  `HAS_PREREQUISITE`, `PREREQUISITE_FOR`, and the scoped `*_DEPENDENCY_OF` relationships.
- SPDX 3: the relationships `dependsOn`, `contains`, `hasDynamicLink`, `hasStaticLink`, `hasPrerequisite`,
  `hasOptionalDependency`, `hasProvidedDependency`, and `hasOptionalComponent`; a package that `describes` other
  packages is composed of them.

Relationships to elements of external documents are ignored with a hint. Cycles are supported.

Components that are not reachable from a described component, for instance because the SBOM has no dependency
relationships at all, are attached to the project as direct dependencies, unless `attachUnreferencedComponents` is
disabled. To keep the structure of unreferenced subgraphs, only their entry points are attached.

## Scopes

The direct dependencies of a project are grouped into scopes:

| Source                                    | Scope                                                             |
| ----------------------------------------- | ----------------------------------------------------------------- |
| CycloneDX component `scope`               | `required` (default), `optional`, `excluded`                      |
| SPDX 2 relationship type                  | `build`, `dev`, `test`, `runtime`, `optional`, `provided`; else `dependencies` |
| SPDX 3 lifecycle-scoped relationship      | its `scope`, such as `build` or `test`; else `dependencies`        |

Scope excludes and includes of the ORT configuration apply to these scopes.
