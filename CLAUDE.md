# secretscanner — Claude Code context

## What this is

A CLI tool that scans codebases for accidentally committed secrets, credentials,
and sensitive values. Single binary, no runtime, no config required to get started.

Module path: `github.com/aurlaw/secretscanner`  
Go version: 1.22+  
Entry point: `cmd/secretscanner/main.go`

---

## Commands

```bash
make build        # compile to ./secretscanner (ldflags stamp version + commit)
make test         # go test -race ./...
make lint         # go vet ./...
make clean        # remove binary
```

Always run `make test` after completing a task. Always run `make lint` before
considering a task done. Never leave either failing.

---

## Package structure

```
internal/findings/   Severity type, Finding struct, Redact function
internal/patterns/   Pattern struct, RawPattern struct, Compile function
internal/config/     Config struct, defaults, YAML loader, pattern resolution
internal/ignore/     .secretsignore parser and Ignorer matcher
internal/scanner/    Worker pool orchestration, file handling, line scanning
internal/git/        Git repo detection, git ls-files integration
internal/output/     Text and JSON formatters
internal/version/    Version and Commit vars (stamped via ldflags)
cmd/secretscanner/   Cobra root command — wires everything together
```

`internal/` for everything. `cmd/` only wires; no business logic there.

---

## What is already implemented (Phases 1–4)

### `internal/version`
- `var Version = "dev"`, `var Commit = "unknown"` — stamped at build time

### `internal/findings`
- `type Severity int` with constants `Low=1 Medium=2 High=3 Critical=4`
- `func (s Severity) String() string`
- `func ParseSeverity(s string) (Severity, error)` — lowercase input only
- `type Finding struct { File string; Line int; Pattern string; Severity Severity; Preview string }`
- `func Redact(line string, match []int) string` — replaces match with `[REDACTED]`, truncates to 120 chars

### `internal/patterns`
- `type RawPattern struct` — `Name`, `Description`, `Regex string`, `Severity string` with `yaml` tags
- `type Pattern struct` — `Name`, `Description`, `Regex *regexp.Regexp`, `Severity findings.Severity`
- `func Compile(raw RawPattern) (Pattern, error)` — compiles regex, parses severity, wraps errors
- `func BuiltinPatterns() []Pattern` — returns all 15 compiled built-in patterns; do not mutate the returned slice

### `internal/config`
- `type PatternConfig struct { Disable []string; Add []patterns.RawPattern }`
- `type Config struct` — Workers, MaxFileSize, MinFileSize, Format, Severity, NoGit, NoProgress, ExitCode, Include, Exclude, ConfigFile, IgnoreFile, Patterns
- `func Default() Config` — returns runtime defaults (workers=8, max-file-size=1MB, severity=Low, format=text)
- `func Load(path string, base Config) (Config, error)` — merges YAML file onto base; missing file is not an error
- `func ResolvePatterns(cfg Config) ([]patterns.Pattern, error)` — applies disable/add from cfg onto built-in set

When implementing subsequent phases, use these types exactly as defined. Do not
redefine or alias them.

---

## Coding conventions

### Errors
- Always wrap: `fmt.Errorf("context: %w", err)`
- Never discard or replace errors silently
- `log.Fatal` and `os.Exit` only in `main.go` — everywhere else return errors

### Panics
- Only permitted in `internal/patterns/builtin.go` for regex compilation failures
- Built-in patterns are programmer-controlled; a bad regex there is a bug, not a runtime error

### Types
- No `interface{}` or `any` — be explicit
- No `err` shadowing with `:=` in the same scope — use a new name or plain `=`

### Global state
- None, except the compiled built-in pattern slice in `builtin.go` (read-only after init)
- Pass dependencies explicitly — no package-level vars that get mutated

### Regex
- Compile once at startup via `regexp.MustCompile` or `Compile()`
- Never call `regexp.Compile` inside a loop or per-file

### Concurrency
- Declare channel directions in function signatures: `chan<- T` send-only, `<-chan T` receive-only
- Worker pool coordination via `sync.WaitGroup` — not done channels
- Always run tests with `-race`: `go test -race ./...`

### `context.Context`
- Not needed in v1 — no HTTP calls, no timeouts. Do not introduce it prematurely.

---

## Testing conventions

- External test packages everywhere: `package foo_test` not `package foo`
- Table-driven tests with `t.Run(tc.name, ...)` sub-tests
- `t.TempDir()` for any test needing the filesystem — never write to the repo
- Static fixture files go in `testdata/` inside the relevant package directory
- For git integration tests: check `exec.LookPath("git")` and call `t.Skip` if absent
- Every task must leave `go test -race ./...` green before moving to the next

### Credential-shaped test fixtures

**Never write a credential-shaped string as a literal in source.** GitHub push
protection scans committed files and will block pushes containing strings that
match real secret patterns — even in test files. This project is a secret
scanner, so its test fixtures are especially likely to trigger this.

The rule: if a test string would make a human think "that looks like a real
credential", construct it at runtime using `strings.Repeat` or split-string
concatenation. Never write the complete string as a single literal.

```go
// BAD — the complete literal triggers GitHub push protection
// (not shown here for the same reason)

// GOOD — constructed at runtime, no literal match
matchLine: "sk_" + "live_" + strings.Repeat("a", 24),
```

Patterns that require this treatment in this codebase:

| Pattern | Why |
|---|---|
| `stripe-live-secret` | `sk_live_` prefix triggers Stripe secret key detection |
| `stripe-live-publishable` | `pk_live_` prefix triggers Stripe publishable key detection |
| `sendgrid-api-key` | `SG.` + correct segment lengths triggers SendGrid detection |
| `twilio-account-sid` | `AC` + 32 hex chars triggers Twilio SID detection |
| `github-pat` | `ghp_` + 36 chars triggers GitHub PAT detection |
| `github-oauth` | `gho_` + 36 chars triggers GitHub OAuth detection |

Apply this to any new test fixture that could match a real-world secret format.
When in doubt, construct it — the cost is one `strings.Repeat` call.

---

## Dependencies

```
github.com/spf13/cobra          CLI framework
gopkg.in/yaml.v3                Config file parsing
github.com/dustin/go-humanize   Human-readable file sizes ("1MB" → int64)
```

Standard library handles everything else: `regexp`, `encoding/json`, `os/exec`,
`path/filepath`, `io/fs`, `sync`, `bufio`, `strings`, `fmt`, `time`, `errors`.

Do not add dependencies without a strong reason.

---

## Phase document workflow

Implementation is broken into phases. Each phase arrives as a self-contained
document with exact task definitions, type signatures to respect, and a clear
"done when" condition. Complete tasks in order. Each task must leave the
codebase in a green state before starting the next.