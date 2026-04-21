# secretscanner

`secretscanner` is a developer-focused CLI tool that scans codebases for accidentally
committed secrets, credentials, and sensitive values. It walks a directory tree
concurrently, matches file contents against a curated set of regex patterns, and
reports findings with file path, line number, pattern name, severity, and a redacted
preview of the matched line.

It ships with a sensible default pattern set covering the most common credential types
and supports user-defined patterns via a config file. A `.secretsignore` file allows
teams to whitelist known false positives without modifying the pattern set.



## Installation

TODO

---

## Usage

TODO

## Flags

TODO

---

## Development

### Prerequisites
- Go 1.22+
- [GoReleaser](https://goreleaser.com) (for releases only)

```bash
brew install goreleaser
```

### Commands

TODO

### Releasing

Releases are automated via GoReleaser and GitHub Actions. Pushing a version
tag triggers a full build for all platforms and publishes a GitHub Release.

```bash
git tag v1.0.0
git push origin v1.0.0
```

Binaries are stamped with the tag version at build time. Local builds without
GoReleaser report `dev` as the version:

```bash
secretscanner --version
# secretscanner version dev
```


