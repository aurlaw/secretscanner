package ignore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aurlaw/secretscanner/internal/ignore"
)

func writeIgnoreFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".secretsignore")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Parse tests

func TestParse_EmptyFile(t *testing.T) {
	path := writeIgnoreFile(t, "")
	rules, err := ignore.Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("len = %d, want 0", len(rules))
	}
}

func TestParse_MissingFile(t *testing.T) {
	rules, err := ignore.Parse("/nonexistent/path/.secretsignore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("len = %d, want 0", len(rules))
	}
}

func TestParse_SkipsBlankAndCommentLines(t *testing.T) {
	path := writeIgnoreFile(t, `
# this is a comment

  # indented comment

`)
	rules, err := ignore.Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("len = %d, want 0", len(rules))
	}
}

func TestParse_GlobRule(t *testing.T) {
	path := writeIgnoreFile(t, "test/fixtures/**\n")
	rules, err := ignore.Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len = %d, want 1", len(rules))
	}
	rule, ok := rules[0].(ignore.GlobRule)
	if !ok {
		t.Fatalf("expected GlobRule, got %T", rules[0])
	}
	if rule.Glob != "test/fixtures/**" {
		t.Errorf("Glob = %q, want test/fixtures/**", rule.Glob)
	}
}

func TestParse_PatternGlobRule(t *testing.T) {
	path := writeIgnoreFile(t, "jwt:test/**\n")
	rules, err := ignore.Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len = %d, want 1", len(rules))
	}
	rule, ok := rules[0].(ignore.PatternGlobRule)
	if !ok {
		t.Fatalf("expected PatternGlobRule, got %T", rules[0])
	}
	if rule.PatternName != "jwt" {
		t.Errorf("PatternName = %q, want jwt", rule.PatternName)
	}
	if rule.Glob != "test/**" {
		t.Errorf("Glob = %q, want test/**", rule.Glob)
	}
}

func TestParse_MixedRules(t *testing.T) {
	path := writeIgnoreFile(t, `# comment line

test/fixtures/**
jwt:test/**
vendor/**
`)
	rules, err := ignore.Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("len = %d, want 3", len(rules))
	}

	r0, ok := rules[0].(ignore.GlobRule)
	if !ok {
		t.Fatalf("rules[0]: expected GlobRule, got %T", rules[0])
	}
	if r0.Glob != "test/fixtures/**" {
		t.Errorf("rules[0].Glob = %q, want test/fixtures/**", r0.Glob)
	}

	r1, ok := rules[1].(ignore.PatternGlobRule)
	if !ok {
		t.Fatalf("rules[1]: expected PatternGlobRule, got %T", rules[1])
	}
	if r1.PatternName != "jwt" || r1.Glob != "test/**" {
		t.Errorf("rules[1] = {%q, %q}, want {jwt, test/**}", r1.PatternName, r1.Glob)
	}

	r2, ok := rules[2].(ignore.GlobRule)
	if !ok {
		t.Fatalf("rules[2]: expected GlobRule, got %T", rules[2])
	}
	if r2.Glob != "vendor/**" {
		t.Errorf("rules[2].Glob = %q, want vendor/**", r2.Glob)
	}
}

// Ignorer tests

func TestIgnorer_GlobRule_Match(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{
		ignore.GlobRule{Glob: "test/*"},
	})
	if !ig.ShouldIgnore("test/foo.go", "aws-access-key", "") {
		t.Error("expected ShouldIgnore = true")
	}
}

func TestIgnorer_GlobRule_NoMatch(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{
		ignore.GlobRule{Glob: "test/*"},
	})
	if ig.ShouldIgnore("cmd/main.go", "aws-access-key", "") {
		t.Error("expected ShouldIgnore = false")
	}
}

func TestIgnorer_PatternGlobRule_Match(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{
		ignore.PatternGlobRule{PatternName: "jwt", Glob: "test/*"},
	})
	if !ig.ShouldIgnore("test/foo.go", "jwt", "") {
		t.Error("expected ShouldIgnore = true")
	}
}

func TestIgnorer_PatternGlobRule_WrongPattern(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{
		ignore.PatternGlobRule{PatternName: "jwt", Glob: "test/*"},
	})
	if ig.ShouldIgnore("test/foo.go", "aws-access-key", "") {
		t.Error("expected ShouldIgnore = false for wrong pattern name")
	}
}

func TestIgnorer_PatternGlobRule_WrongFile(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{
		ignore.PatternGlobRule{PatternName: "jwt", Glob: "test/*"},
	})
	if ig.ShouldIgnore("cmd/main.go", "jwt", "") {
		t.Error("expected ShouldIgnore = false for non-matching file")
	}
}

func TestIgnorer_InlineMarker_Match(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{})
	if !ig.ShouldIgnore("cmd/main.go", "jwt", "token := value // secretscanner:ignore") {
		t.Error("expected ShouldIgnore = true for inline marker")
	}
}

func TestIgnorer_InlineMarker_NoMatch(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{})
	if ig.ShouldIgnore("cmd/main.go", "jwt", "token := value") {
		t.Error("expected ShouldIgnore = false when no inline marker")
	}
}

func TestIgnorer_EmptyRules_InlineMarkerStillActive(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{})
	if !ig.ShouldIgnore("cmd/main.go", "jwt", "x // secretscanner:ignore") {
		t.Error("expected inline marker to be active even with no rules")
	}
}

func TestIgnorer_NoMatch(t *testing.T) {
	ig := ignore.NewIgnorer([]ignore.Rule{
		ignore.GlobRule{Glob: "test/*"},
	})
	if ig.ShouldIgnore("cmd/main.go", "jwt", "token := value") {
		t.Error("expected ShouldIgnore = false when no rule matches")
	}
}
