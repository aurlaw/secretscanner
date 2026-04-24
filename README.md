# secretscanner

A fast, zero-config CLI tool that scans codebases for accidentally committed secrets and credentials.

![Test](https://github.com/aurlaw/secretscanner/actions/workflows/test.yml/badge.svg)

## Features

- Concurrent scanning with a configurable worker pool
- Git-aware mode — respects `.gitignore` via `git ls-files`
- 15 built-in patterns covering the most common credential types
- Redacted preview lines — matched values never appear in output
- `.secretsignore` support for whitelisting known false positives
- Extensible via YAML config — disable built-ins, add custom patterns
- Text and JSON output formats
- Clean exit code contract for CI integration (`--exit-code`)
- Single static binary, no runtime dependency

## Installation

### go install

```bash
go install github.com/aurlaw/secretscanner@latest
```

### GitHub Releases

Download the binary for your platform from the [Releases page](https://github.com/aurlaw/secretscanner/releases).

### Build from source

```bash
git clone https://github.com/aurlaw/secretscanner.git
cd secretscanner
make build
```

## Quick start

Scan the current directory:

```bash
secretscanner .
```

Scan with JSON output (useful for piping to other tools):

```bash
secretscanner --format json .
```

Use as a CI gate — exits with code 1 if any findings exist:

```bash
secretscanner --exit-code --severity high .
```

## Example output

```
findings in 2 files

.env:3  [critical]  stripe-live-secret-key
  STRIPE_SECRET_KEY=sk_live_[REDACTED]

cmd/config.go:14  [critical]  aws-access-key
  export AWS_ACCESS_KEY_ID="AKIA[REDACTED]"

---
files scanned:       842
files skipped:         5
findings:              2
critical:              2
elapsed:           0.847s
```

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--workers` | `8` | Number of concurrent scanning goroutines |
| `--config` | `.secretscanner.yaml` | Path to config file |
| `--ignore-file` | `.secretsignore` | Path to ignore file |
| `--format` | `text` | Output format: `text` or `json` |
| `--severity` | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `--max-file-size` | `1MB` | Skip files larger than this size |
| `--min-size` | `0` | Skip files smaller than this size |
| `--no-git` | `false` | Disable git-aware mode |
| `--no-progress` | `false` | Suppress progress output |
| `--exit-code` | `false` | Exit with code 1 if findings exist |
| `--include` | | Glob patterns for files to include |
| `--exclude` | | Glob patterns for files to exclude |

## Configuration

Place `.secretscanner.yaml` in the root of the directory you are scanning:

```yaml
settings:
  workers: 8
  max-file-size: 2MB
  severity: high

patterns:
  disable:
    - jwt             # too many false positives
  add:
    - name: internal-api-key
      description: Internal service API key
      regex: 'INT-[A-Z]{4}-[0-9]{16}'
      severity: critical
```

## .secretsignore

Create a `.secretsignore` file to suppress known false positives:

```
# Ignore all findings in test fixture files
test/fixtures/**

# Ignore jwt findings in all test files
jwt:test/**

# Inline suppression — add to the end of any source line
var token = loadFromEnv() // secretscanner:ignore
```

Three rule types are supported:

- **Glob** — suppresses all findings in matching files: `vendor/**`
- **Pattern:Glob** — suppresses a specific pattern in matching files: `jwt:test/**`
- **Inline marker** — suppresses a single line: `// secretscanner:ignore`

## Built-in patterns

| Pattern | Severity |
|---|---|
| AWS access key | critical |
| AWS secret key | critical |
| GitHub personal access token | critical |
| GitHub OAuth token | critical |
| Stripe live secret key | critical |
| Private key PEM header | critical |
| SendGrid API key | critical |
| Stripe live publishable key | high |
| Generic API key assignment | high |
| Generic secret assignment | high |
| Generic password assignment | high |
| Slack token | high |
| Connection string with credentials | high |
| Twilio account SID | high |
| JWT token | medium |

## License

MIT — see [LICENSE](LICENSE)
