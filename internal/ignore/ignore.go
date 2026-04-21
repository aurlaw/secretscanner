package ignore

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Rule is implemented by all ignore rule types.
// The unexported method seals the interface — only this package can
// create Rule values.
type Rule interface {
	ruleType() string
}

// GlobRule suppresses all findings in files whose path matches Glob.
// Example .secretsignore entry: test/fixtures/**
type GlobRule struct {
	Glob string
}

// PatternGlobRule suppresses findings for a specific pattern name in
// files whose path matches Glob.
// Example .secretsignore entry: jwt:test/**
type PatternGlobRule struct {
	PatternName string
	Glob        string
}

// InlineMarker suppresses a finding when the scanned source line
// contains the string "secretscanner:ignore". It is injected
// automatically by NewIgnorer — it does not appear in .secretsignore.
type InlineMarker struct{}

func (GlobRule) ruleType() string        { return "glob" }
func (PatternGlobRule) ruleType() string { return "pattern-glob" }
func (InlineMarker) ruleType() string    { return "inline" }

// Parse reads a .secretsignore file and returns the rules it defines.
// If path does not exist, an empty slice and nil error are returned.
func Parse(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return []Rule{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ignore: parse %q: %w", path, err)
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(trimmed, ":"); idx >= 0 {
			rules = append(rules, PatternGlobRule{
				PatternName: trimmed[:idx],
				Glob:        trimmed[idx+1:],
			})
		} else {
			rules = append(rules, GlobRule{Glob: trimmed})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ignore: parse %q: %w", path, err)
	}
	return rules, nil
}

// Ignorer matches findings against a set of ignore rules.
type Ignorer struct {
	rules []Rule
}

// NewIgnorer creates an Ignorer from the provided rules, always prepending
// an InlineMarker so inline suppression is active regardless of file contents.
func NewIgnorer(rules []Rule) Ignorer {
	all := make([]Rule, 0, len(rules)+1)
	all = append(all, InlineMarker{})
	all = append(all, rules...)
	return Ignorer{rules: all}
}

// ShouldIgnore returns true if any rule suppresses the finding described
// by file, patternName, and lineContent.
func (ig Ignorer) ShouldIgnore(file, patternName, lineContent string) bool {
	for _, rule := range ig.rules {
		switch r := rule.(type) {
		case GlobRule:
			matched, _ := filepath.Match(r.Glob, file)
			if matched {
				return true
			}
		case PatternGlobRule:
			if r.PatternName == patternName {
				matched, _ := filepath.Match(r.Glob, file)
				if matched {
					return true
				}
			}
		case InlineMarker:
			if strings.Contains(lineContent, "secretscanner:ignore") {
				return true
			}
		}
	}
	return false
}
