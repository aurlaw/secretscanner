package scanner_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/aurlaw/secretscanner/internal/ignore"
	"github.com/aurlaw/secretscanner/internal/patterns"
	"github.com/aurlaw/secretscanner/internal/scanner"
)

// testPattern returns a Pattern that matches "TESTKEY-" followed by
// exactly 8 uppercase letters. This shape does not resemble any real
// credential and will not trigger GitHub push protection.
func testPattern(t *testing.T) patterns.Pattern {
	t.Helper()
	p, err := patterns.Compile(patterns.RawPattern{
		Name:     "test-key",
		Regex:    `TESTKEY-[A-Z]{8}`,
		Severity: "high",
	})
	if err != nil {
		t.Fatalf("testPattern: %v", err)
	}
	return p
}

// IsBinary tests

func TestIsBinary_BinaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.bin")
	content := append([]byte("some text"), 0x00, 0x01, 0x02)
	os.WriteFile(path, content, 0644)

	got, err := scanner.IsBinary(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected IsBinary = true")
	}
}

func TestIsBinary_TextFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "text.go")
	os.WriteFile(path, []byte("package main\n\nfunc main() {}\n"), 0644)

	got, err := scanner.IsBinary(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected IsBinary = false for text file")
	}
}

func TestIsBinary_LargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")
	// null byte at position 0, file is 16384 bytes total
	content := make([]byte, 16384)
	content[0] = 0x00
	os.WriteFile(path, content, 0644)

	got, err := scanner.IsBinary(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected IsBinary = true")
	}
}

func TestIsBinary_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	os.WriteFile(path, []byte{}, 0644)

	got, err := scanner.IsBinary(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected IsBinary = false for empty file")
	}
}

// WithinSizeLimit tests

func TestWithinSizeLimit_Within(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0644)

	got, err := scanner.WithinSizeLimit(path, 50, 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected WithinSizeLimit = true")
	}
}

func TestWithinSizeLimit_TooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 300), 0644)

	got, err := scanner.WithinSizeLimit(path, 0, 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected WithinSizeLimit = false for oversized file")
	}
}

func TestWithinSizeLimit_TooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 10), 0644)

	got, err := scanner.WithinSizeLimit(path, 50, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected WithinSizeLimit = false for undersized file")
	}
}

func TestWithinSizeLimit_NoMax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 1000), 0644)

	got, err := scanner.WithinSizeLimit(path, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected WithinSizeLimit = true with max=0")
	}
}

func TestWithinSizeLimit_NoMin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 5), 0644)

	got, err := scanner.WithinSizeLimit(path, 0, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected WithinSizeLimit = true with min=0")
	}
}

func TestWithinSizeLimit_NoLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0644)

	got, err := scanner.WithinSizeLimit(path, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected WithinSizeLimit = true with no limits")
	}
}

func TestWithinSizeLimit_ExactlyAtMax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0644)

	got, err := scanner.WithinSizeLimit(path, 0, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected WithinSizeLimit = true when size == max")
	}
}

// ScanLines tests

func TestScanLines_SingleMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.go")
	content := "package main\n\nvar key = \"TESTKEY-ABCDEFGH\"\n"
	os.WriteFile(path, []byte(content), 0644)

	pats := []patterns.Pattern{testPattern(t)}
	ig := ignore.NewIgnorer(nil)

	got, err := scanner.ScanLines(path, pats, ig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Line != 3 {
		t.Errorf("Line = %d, want 3", got[0].Line)
	}
	if got[0].Pattern != "test-key" {
		t.Errorf("Pattern = %q, want test-key", got[0].Pattern)
	}
	if got[0].File != path {
		t.Errorf("File = %q, want %q", got[0].File, path)
	}
}

func TestScanLines_NoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.go")
	os.WriteFile(path, []byte("package main\n\nfunc main() {}\n"), 0644)

	got, err := scanner.ScanLines(path, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

func TestScanLines_TwoPatternsOnOneLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.go")
	// Line matches both patterns
	os.WriteFile(path, []byte("TESTKEY-ABCDEFGH TESTKEY2-ABCDEFGH\n"), 0644)

	p2, err := patterns.Compile(patterns.RawPattern{
		Name:     "test-key-2",
		Regex:    `TESTKEY2-[A-Z]{8}`,
		Severity: "high",
	})
	if err != nil {
		t.Fatalf("compile pattern 2: %v", err)
	}

	pats := []patterns.Pattern{testPattern(t), p2}
	got, err := scanner.ScanLines(path, pats, ignore.NewIgnorer(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
}

func TestScanLines_InlineIgnore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inline.go")
	content := "var key = \"TESTKEY-ABCDEFGH\" // secretscanner:ignore\n"
	os.WriteFile(path, []byte(content), 0644)

	got, err := scanner.ScanLines(path, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

func TestScanLines_GlobIgnore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.go")
	os.WriteFile(path, []byte("var key = \"TESTKEY-ABCDEFGH\"\n"), 0644)

	ig := ignore.NewIgnorer([]ignore.Rule{
		ignore.GlobRule{Glob: filepath.Join(dir, "*")},
	})

	got, err := scanner.ScanLines(path, []patterns.Pattern{testPattern(t)}, ig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

func TestScanLines_LineNumbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lines.go")
	content := "line one\n\nline three\nTESTKEY-ABCDEFGH\nline five\n"
	os.WriteFile(path, []byte(content), 0644)

	got, err := scanner.ScanLines(path, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Line != 4 {
		t.Errorf("Line = %d, want 4", got[0].Line)
	}
}

func TestScanLines_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.go")
	os.WriteFile(path, []byte{}, 0644)

	got, err := scanner.ScanLines(path, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

func TestScanLines_FindingFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "path_check.go")
	os.WriteFile(path, []byte("TESTKEY-ABCDEFGH\n"), 0644)

	got, err := scanner.ScanLines(path, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].File != path {
		t.Errorf("File = %q, want %q", got[0].File, path)
	}
}
