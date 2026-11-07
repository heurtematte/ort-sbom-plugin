# Supported formats

| Format    | Serializations             | Tested versions | Media type                                   |
| --------- | -------------------------- | --------------- | -------------------------------------------- |
| CycloneDX | JSON                       | 1.2 to 1.7      | `application/vnd.cyclonedx+json`             |
| CycloneDX | XML                        | 1.0 to 1.7      | `application/vnd.cyclonedx+xml`              |
| SPDX      | JSON                       | 2.0 to 2.3      | `application/spdx+json`                      |
| SPDX      | YAML                       | 2.0 to 2.3      | `application/spdx+yaml`                      |
| SPDX      | tag-value                  | 2.0 to 2.3      | `text/spdx`                                  |
| SPDX      | XML                        | 2.0 to 2.3      | `application/spdx+xml`                       |
| SPDX      | JSON-LD                    | 3.0.0, 3.0.1    | `application/spdx+json`                      |

CycloneDX 1.0 and 1.1 only exist as XML. Documents may be encoded in **UTF-8, UTF-16, or UTF-32**, with or without a
byte order mark.

## No need to specify the format

The format and the specification version never need to be specified, because every supported format identifies
itself in its content:

| Format              | Identified by                                                         |
| ------------------- | --------------------------------------------------------------------- |
| CycloneDX JSON      | `"bomFormat": "CycloneDX"` and `specVersion`                          |
| CycloneDX XML       | the namespace `http://cyclonedx.org/schema/bom/<version>`             |
| SPDX 2 JSON, YAML   | `spdxVersion`                                                         |
| SPDX 2 tag-value    | `SPDXVersion:`                                                        |
| SPDX 2 XML          | the root element `Document` with `spdxVersion`                        |
| SPDX 3 JSON-LD      | the JSON-LD context `https://spdx.org/rdf/3.*` and `CreationInfo.specVersion` |

File names are therefore irrelevant for parsing; they only decide which files the package manager looks at (see
[configuration](configuration.md)). The detected format and version are available in the parsed document.

## Versions that have not been tested

Documents with a version that has not been tested, such as a future CycloneDX version, are not rejected: they are
interpreted like the closest tested version, and a warning is reported. Each format family keeps backward-compatible
structures across its minor versions, so this usually works.

## Tolerance

SBOMs found in the wild often violate their specification in ways that do not matter for the ingestion. The parsers are
lenient where possible:

- A CycloneDX BOM whose `timestamp` or `serialNumber` cannot be interpreted is parsed without these values, with a
  warning.
- SPDX documents are read from their structure without enforcing constraints that are irrelevant here, such as the
  format of checksums or required fields like `copyrightText`.
- SPDX 3 documents may be a graph (`@graph`) or a single element, and elements may be nested inline.
- Hash values that do not match their algorithm are ignored.

## Unsupported formats

| Format                         | Alternative                                                    |
| ------------------------------ | -------------------------------------------------------------- |
| SPDX 2 RDF/XML                 | Convert to SPDX JSON, for instance with the SPDX tools.         |
| CycloneDX Protocol Buffers     | Convert to CycloneDX JSON, for instance with the CycloneDX CLI. |

Such documents are rejected with a message naming the format.
