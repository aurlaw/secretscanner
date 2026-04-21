package patterns_test

import (
	"testing"

	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/patterns"
)

func TestCompile(t *testing.T) {
	tests := []struct {
		name        string
		raw         patterns.RawPattern
		wantErr     bool
		wantSev     findings.Severity
		matchLine   string
		shouldMatch bool
	}{
		{
			name: "valid pattern compiles and matches",
			raw: patterns.RawPattern{
				Name:        "test-key",
				Description: "A test key pattern",
				Regex:       `AKIA[0-9A-Z]{16}`,
				Severity:    "critical",
			},
			wantSev:     findings.Critical,
			matchLine:   "AKIAIOSFODNN7EXAMPLE",
			shouldMatch: true,
		},
		{
			name: "valid pattern does not match unrelated line",
			raw: patterns.RawPattern{
				Name:     "test-key",
				Regex:    `AKIA[0-9A-Z]{16}`,
				Severity: "high",
			},
			wantSev:     findings.High,
			matchLine:   "nothing interesting here",
			shouldMatch: false,
		},
		{
			name: "invalid regex returns error",
			raw: patterns.RawPattern{
				Name:     "bad-regex",
				Regex:    `[invalid(`,
				Severity: "low",
			},
			wantErr: true,
		},
		{
			name: "invalid severity returns error",
			raw: patterns.RawPattern{
				Name:     "bad-severity",
				Regex:    `foo`,
				Severity: "extreme",
			},
			wantErr: true,
		},
		{
			name: "empty severity returns error",
			raw: patterns.RawPattern{
				Name:     "no-severity",
				Regex:    `foo`,
				Severity: "",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := patterns.Compile(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Compile(%q): expected error, got nil", tc.raw.Name)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile(%q): unexpected error: %v", tc.raw.Name, err)
			}

			if got.Name != tc.raw.Name {
				t.Errorf("Name = %q, want %q", got.Name, tc.raw.Name)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("Severity = %v, want %v", got.Severity, tc.wantSev)
			}
			if got.Regex == nil {
				t.Fatal("Regex is nil")
			}

			matched := got.Regex.MatchString(tc.matchLine)
			if matched != tc.shouldMatch {
				t.Errorf("Regex.MatchString(%q) = %v, want %v", tc.matchLine, matched, tc.shouldMatch)
			}
		})
	}
}
