package findings_test

import (
	"strings"
	"testing"

	"github.com/aurlaw/secretscanner/internal/findings"
)

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    findings.Severity
		wantErr bool
	}{
		{name: "low", input: "low", want: findings.Low},
		{name: "medium", input: "medium", want: findings.Medium},
		{name: "high", input: "high", want: findings.High},
		{name: "critical", input: "critical", want: findings.Critical},
		{name: "empty string", input: "", wantErr: true},
		{name: "uppercase", input: "HIGH", wantErr: true},
		{name: "unknown value", input: "extreme", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findings.ParseSeverity(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseSeverity(%q): expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSeverity(%q): unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("ParseSeverity(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  findings.Severity
		want string
	}{
		{findings.Low, "low"},
		{findings.Medium, "medium"},
		{findings.High, "high"},
		{findings.Critical, "critical"},
		{findings.Severity(99), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.sev.String(); got != tc.want {
				t.Errorf("Severity(%d).String() = %q, want %q", tc.sev, got, tc.want)
			}
		})
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(findings.Low < findings.Medium) {
		t.Error("expected Low < Medium")
	}
	if !(findings.Medium < findings.High) {
		t.Error("expected Medium < High")
	}
	if !(findings.High < findings.Critical) {
		t.Error("expected High < Critical")
	}
}

// ---------------------------------------------------------------------------
// Redact
// ---------------------------------------------------------------------------

func TestRedact(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		match [2]int
		want  string
	}{
		{
			name:  "match at start",
			line:  `AKIAIOSFODNN7EXAMPLE rest of line`,
			match: [2]int{0, 20},
			want:  `[REDACTED] rest of line`,
		},
		{
			name:  "match in middle",
			line:  `export AWS_KEY="AKIAIOSFODNN7EXAMPLE" # comment`,
			match: [2]int{16, 36},
			want:  `export AWS_KEY="[REDACTED]" # comment`,
		},
		{
			name:  "match at end",
			line:  `key=AKIAIOSFODNN7EXAMPLE`,
			match: [2]int{4, 24},
			want:  `key=[REDACTED]`,
		},
		{
			name:  "full line match",
			line:  `AKIAIOSFODNN7EXAMPLE`,
			match: [2]int{0, 20},
			want:  `[REDACTED]`,
		},
		{
			name:  "result truncated to 120 chars",
			line:  `key="AKIAIOSFODNN7EXAMPLE"` + strings.Repeat("x", 120),
			match: [2]int{5, 25},
			want:  (`key="[REDACTED]"` + strings.Repeat("x", 120))[:120],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findings.Redact(tc.line, tc.match[:])
			if got != tc.want {
				t.Errorf("Redact() =\n  %q\nwant\n  %q", got, tc.want)
			}
			if len(got) > 120 {
				t.Errorf("Redact() result length %d exceeds 120", len(got))
			}
		})
	}
}
