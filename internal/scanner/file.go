package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/ignore"
	"github.com/aurlaw/secretscanner/internal/patterns"
)

const binarySampleSize = 8192

// IsBinary returns true if the first 8192 bytes of path contain a null byte.
func IsBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("scanner: binary check %q: %w", path, err)
	}
	defer f.Close()

	buf := make([]byte, binarySampleSize)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("scanner: binary check %q: %w", path, err)
	}
	return bytes.IndexByte(buf[:n], 0x00) >= 0, nil
}

// WithinSizeLimit returns true if the file at path has a size within [min, max].
// A min of 0 means no lower bound; a max of 0 means no upper bound.
func WithinSizeLimit(path string, min, max int64) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("scanner: size check %q: %w", path, err)
	}
	size := info.Size()
	if min != 0 && size < min {
		return false, nil
	}
	if max != 0 && size > max {
		return false, nil
	}
	return true, nil
}

// ScanLines opens path, checks each line against every pattern, and returns
// all findings not suppressed by the ignorer.
func ScanLines(path string, pats []patterns.Pattern, ignorer ignore.Ignorer) ([]findings.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner: scan %q: %w", path, err)
	}
	defer f.Close()

	var results []findings.Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		for _, pat := range pats {
			match := pat.Regex.FindStringIndex(line)
			if match == nil {
				continue
			}
			if ignorer.ShouldIgnore(path, pat.Name, line) {
				continue
			}
			results = append(results, findings.Finding{
				File:     path,
				Line:     lineNum,
				Pattern:  pat.Name,
				Severity: pat.Severity,
				Preview:  findings.Redact(line, match),
			})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
