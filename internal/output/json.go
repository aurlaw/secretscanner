package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/scanner"
)

type jsonOutput struct {
	Findings []jsonFinding `json:"findings"`
	Summary  jsonSummary   `json:"summary"`
}

type jsonFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Preview  string `json:"preview"`
}

type jsonSummary struct {
	FilesScanned  int   `json:"filesScanned"`
	FilesSkipped  int   `json:"filesSkipped"`
	TotalFindings int   `json:"totalFindings"`
	Critical      int   `json:"critical"`
	High          int   `json:"high"`
	Medium        int   `json:"medium"`
	Low           int   `json:"low"`
	ElapsedMs     int64 `json:"elapsedMs"`
}

// WriteJSON writes structured JSON scan output to w.
func WriteJSON(w io.Writer, found []findings.Finding, summary scanner.ScanSummary) error {
	jf := make([]jsonFinding, 0, len(found))
	counts := map[findings.Severity]int{}
	for _, f := range found {
		jf = append(jf, jsonFinding{
			File:     f.File,
			Line:     f.Line,
			Pattern:  f.Pattern,
			Severity: f.Severity.String(),
			Preview:  f.Preview,
		})
		counts[f.Severity]++
	}

	out := jsonOutput{
		Findings: jf,
		Summary: jsonSummary{
			FilesScanned:  summary.FilesScanned,
			FilesSkipped:  summary.FilesSkipped,
			TotalFindings: len(found),
			Critical:      counts[findings.Critical],
			High:          counts[findings.High],
			Medium:        counts[findings.Medium],
			Low:           counts[findings.Low],
			ElapsedMs:     summary.Elapsed.Milliseconds(),
		},
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("output: json marshal: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
