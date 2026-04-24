package output

import (
	"fmt"
	"io"

	humanize "github.com/dustin/go-humanize"

	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/scanner"
)

// WriteText writes human-readable scan output to w.
func WriteText(w io.Writer, found []findings.Finding, summary scanner.ScanSummary) {
	// Header
	if len(found) == 0 {
		fmt.Fprintf(w, "no findings\n\n")
	} else {
		unique := make(map[string]struct{}, len(found))
		for _, f := range found {
			unique[f.File] = struct{}{}
		}
		fmt.Fprintf(w, "findings in %d files\n\n", len(unique))
	}

	// Per-finding blocks
	for _, f := range found {
		fmt.Fprintf(w, "%s:%d  [%s]  %s\n", f.File, f.Line, f.Severity, f.Pattern)
		fmt.Fprintf(w, "  %s\n", f.Preview)
		fmt.Fprintln(w)
	}

	// Summary block
	fmt.Fprintln(w, "---")
	fmt.Fprintf(w, "files scanned:  %6s\n", humanize.Comma(int64(summary.FilesScanned)))
	fmt.Fprintf(w, "files skipped:  %6s\n", humanize.Comma(int64(summary.FilesSkipped)))
	fmt.Fprintf(w, "findings:       %6d\n", len(found))

	// Severity breakdown — only non-zero levels, in descending order.
	counts := map[findings.Severity]int{}
	for _, f := range found {
		counts[f.Severity]++
	}
	for _, sev := range []findings.Severity{findings.Critical, findings.High, findings.Medium, findings.Low} {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(w, "%s:     %6d\n", sev, n)
		}
	}

	fmt.Fprintf(w, "elapsed:        %6.3fs\n", summary.Elapsed.Seconds())
}
