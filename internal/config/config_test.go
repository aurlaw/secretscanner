package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aurlaw/secretscanner/internal/config"
	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/patterns"
)

func TestDefault(t *testing.T) {
	d := config.Default()

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"Workers", d.Workers, 8},
		{"MaxFileSize", d.MaxFileSize, int64(1 << 20)},
		{"MinFileSize", d.MinFileSize, int64(0)},
		{"Format", d.Format, "text"},
		{"Severity", d.Severity, findings.Low},
		{"NoGit", d.NoGit, false},
		{"NoProgress", d.NoProgress, false},
		{"ExitCode", d.ExitCode, false},
		{"ConfigFile", d.ConfigFile, ".secretscanner.yaml"},
		{"IgnoreFile", d.IgnoreFile, ".secretsignore"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("Default().%s = %v, want %v", tc.name, tc.got, tc.want)
			}
		})
	}

	t.Run("Include", func(t *testing.T) {
		if d.Include != nil {
			t.Errorf("Default().Include = %v, want nil", d.Include)
		}
	})
	t.Run("Exclude", func(t *testing.T) {
		if d.Exclude != nil {
			t.Errorf("Default().Exclude = %v, want nil", d.Exclude)
		}
	})
}

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_MissingFile(t *testing.T) {
	base := config.Default()
	got, err := config.Load("/nonexistent/path/config.yaml", base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Workers != base.Workers || got.Format != base.Format {
		t.Error("Load with missing file should return base config unchanged")
	}
}

func TestLoad_PartialOverride(t *testing.T) {
	path := writeYAML(t, `
settings:
  workers: 4
`)
	base := config.Default()
	got, err := config.Load(path, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Workers != 4 {
		t.Errorf("Workers = %d, want 4", got.Workers)
	}
	// Fields not in YAML should retain base values.
	if got.Format != base.Format {
		t.Errorf("Format = %q, want %q", got.Format, base.Format)
	}
	if got.MaxFileSize != base.MaxFileSize {
		t.Errorf("MaxFileSize = %d, want %d", got.MaxFileSize, base.MaxFileSize)
	}
}

func TestLoad_AllSettingsFields(t *testing.T) {
	path := writeYAML(t, `
settings:
  workers: 16
  max-file-size: "2MB"
  min-size: "1B"
  format: json
  severity: high
  no-git: true
  no-progress: true
  exit-code: true
  include:
    - "**/*.go"
  exclude:
    - "vendor/**"
`)
	got, err := config.Load(path, config.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.Workers != 16 {
		t.Errorf("Workers = %d, want 16", got.Workers)
	}
	if got.MaxFileSize != 2000000 {
		t.Errorf("MaxFileSize = %d, want 2000000", got.MaxFileSize)
	}
	if got.MinFileSize != 1 {
		t.Errorf("MinFileSize = %d, want 1", got.MinFileSize)
	}
	if got.Format != "json" {
		t.Errorf("Format = %q, want json", got.Format)
	}
	if got.Severity != findings.High {
		t.Errorf("Severity = %v, want high", got.Severity)
	}
	if !got.NoGit {
		t.Error("NoGit = false, want true")
	}
	if !got.NoProgress {
		t.Error("NoProgress = false, want true")
	}
	if !got.ExitCode {
		t.Error("ExitCode = false, want true")
	}
	if len(got.Include) != 1 || got.Include[0] != "**/*.go" {
		t.Errorf("Include = %v, want [**/*.go]", got.Include)
	}
	if len(got.Exclude) != 1 || got.Exclude[0] != "vendor/**" {
		t.Errorf("Exclude = %v, want [vendor/**]", got.Exclude)
	}
}

func TestLoad_SizeStrings(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"1MB", 1000000},
		{"500KB", 500000},
		{"2MB", 2000000},
		{"1B", 1},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			path := writeYAML(t, "settings:\n  max-file-size: \""+tc.input+"\"\n")
			got, err := config.Load(path, config.Default())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.MaxFileSize != tc.want {
				t.Errorf("MaxFileSize(%q) = %d, want %d", tc.input, got.MaxFileSize, tc.want)
			}
		})
	}
}

func TestLoad_PatternConfig(t *testing.T) {
	path := writeYAML(t, `
patterns:
  disable:
    - jwt
  add:
    - name: internal-api-key
      description: Internal service API key
      regex: 'INT-[A-Z]{4}-[0-9]{16}'
      severity: critical
`)
	got, err := config.Load(path, config.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Patterns.Disable) != 1 || got.Patterns.Disable[0] != "jwt" {
		t.Errorf("Disable = %v, want [jwt]", got.Patterns.Disable)
	}
	if len(got.Patterns.Add) != 1 || got.Patterns.Add[0].Name != "internal-api-key" {
		t.Errorf("Add = %v, want one pattern named internal-api-key", got.Patterns.Add)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeYAML(t, "settings: [not: valid: yaml")
	_, err := config.Load(path, config.Default())
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoad_InvalidSizeString(t *testing.T) {
	path := writeYAML(t, "settings:\n  max-file-size: \"not-a-size\"\n")
	_, err := config.Load(path, config.Default())
	if err == nil {
		t.Error("expected error for invalid size string, got nil")
	}
}

func TestResolvePatterns_Default(t *testing.T) {
	ps, err := config.ResolvePatterns(config.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps) != 15 {
		t.Errorf("len = %d, want 15", len(ps))
	}
}

func TestResolvePatterns_DisableOne(t *testing.T) {
	cfg := config.Default()
	cfg.Patterns.Disable = []string{"jwt"}

	ps, err := config.ResolvePatterns(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps) != 14 {
		t.Errorf("len = %d, want 14", len(ps))
	}
	for _, p := range ps {
		if p.Name == "jwt" {
			t.Error("jwt pattern should have been removed")
		}
	}
}

func TestResolvePatterns_DisableNonExistent(t *testing.T) {
	cfg := config.Default()
	cfg.Patterns.Disable = []string{"does-not-exist"}

	ps, err := config.ResolvePatterns(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps) != 15 {
		t.Errorf("len = %d, want 15", len(ps))
	}
}

func TestResolvePatterns_DisableMultiple(t *testing.T) {
	cfg := config.Default()
	cfg.Patterns.Disable = []string{"jwt", "aws-access-key", "github-pat"}

	ps, err := config.ResolvePatterns(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps) != 12 {
		t.Errorf("len = %d, want 12", len(ps))
	}
}

func TestResolvePatterns_AddCustom(t *testing.T) {
	cfg := config.Default()
	cfg.Patterns.Add = []patterns.RawPattern{
		{
			Name:        "custom-pattern",
			Description: "A custom test pattern",
			Regex:       `CUSTOM-[A-Z]{4}`,
			Severity:    "high",
		},
	}

	ps, err := config.ResolvePatterns(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps) != 16 {
		t.Errorf("len = %d, want 16", len(ps))
	}
	last := ps[len(ps)-1]
	if last.Name != "custom-pattern" {
		t.Errorf("last pattern name = %q, want custom-pattern", last.Name)
	}
}

func TestResolvePatterns_AddInvalidRegex(t *testing.T) {
	cfg := config.Default()
	cfg.Patterns.Add = []patterns.RawPattern{
		{
			Name:     "bad-pattern",
			Regex:    `[invalid(`,
			Severity: "low",
		},
	}

	_, err := config.ResolvePatterns(cfg)
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}
