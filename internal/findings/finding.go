package findings

import "fmt"

// Severity represents the risk level of a finding.
// Defined as int so severities can be compared with >= for filtering.
type Severity int

const (
	Low      Severity = 1
	Medium   Severity = 2
	High     Severity = 3
	Critical Severity = 4
)

// String returns the lowercase name of the severity level.
func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a lowercase string to a Severity value.
// Returns an error for any unrecognised input.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	case "critical":
		return Critical, nil
	default:
		return 0, fmt.Errorf("unknown severity %q: must be one of low, medium, high, critical", s)
	}
}

// maxPreviewLen is the maximum length of a redacted preview line in characters.
const maxPreviewLen = 120

// Finding represents a single matched secret in a file.
type Finding struct {
	File     string
	Line     int
	Pattern  string
	Severity Severity
	Preview  string
}

// Redact replaces the matched portion of line with [REDACTED] and truncates
// the result to maxPreviewLen characters. match is a two-element slice
// [start, end] as returned by regexp.FindStringIndex.
func Redact(line string, match []int) string {
	redacted := line[:match[0]] + "[REDACTED]" + line[match[1]:]
	if len(redacted) > maxPreviewLen {
		redacted = redacted[:maxPreviewLen]
	}
	return redacted
}
