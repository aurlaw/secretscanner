package patterns

import (
	"fmt"
	"regexp"

	"github.com/aurlaw/secretscanner/internal/findings"
)

// RawPattern is the uncompiled representation used in config files and
// for defining the built-in pattern set. Regex is a plain string;
// Severity is a lowercase string ("low", "high", etc.).
type RawPattern struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Regex       string `yaml:"regex"`
	Severity    string `yaml:"severity"`
}

// Pattern is a compiled, ready-to-use pattern with a pre-compiled regex
// and a typed severity level.
type Pattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	Severity    findings.Severity
}

// Compile converts a RawPattern into a Pattern, compiling the regex and
// parsing the severity. Returns an error if either step fails.
func Compile(raw RawPattern) (Pattern, error) {
	re, err := regexp.Compile(raw.Regex)
	if err != nil {
		return Pattern{}, fmt.Errorf("pattern %q: invalid regex: %w", raw.Name, err)
	}

	sev, err := findings.ParseSeverity(raw.Severity)
	if err != nil {
		return Pattern{}, fmt.Errorf("pattern %q: %w", raw.Name, err)
	}

	return Pattern{
		Name:        raw.Name,
		Description: raw.Description,
		Regex:       re,
		Severity:    sev,
	}, nil
}
