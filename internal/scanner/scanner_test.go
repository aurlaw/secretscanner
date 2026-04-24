package scanner_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aurlaw/secretscanner/internal/config"
	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/ignore"
	"github.com/aurlaw/secretscanner/internal/patterns"
	"github.com/aurlaw/secretscanner/internal/scanner"
)

// BuildFileList tests

func TestBuildFileList_WalkDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(dir, "b.go"), []byte("package main"), 0644)

	cfg := config.Default()
	cfg.NoGit = true

	files, err := scanner.BuildFileList(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Errorf("got %d files, want 2", len(files))
	}
}

func TestBuildFileList_IncludeFilter(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("text"), 0644)

	cfg := config.Default()
	cfg.NoGit = true
	cfg.Include = []string{"*.go"}

	files, err := scanner.BuildFileList(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if filepath.Base(files[0]) != "a.go" {
		t.Errorf("got %q, want a.go", filepath.Base(files[0]))
	}
}

func TestBuildFileList_ExcludeFilter(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("text"), 0644)

	cfg := config.Default()
	cfg.NoGit = true
	cfg.Exclude = []string{"*.txt"}

	files, err := scanner.BuildFileList(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if filepath.Base(files[0]) != "a.go" {
		t.Errorf("got %q, want a.go", filepath.Base(files[0]))
	}
}

func TestBuildFileList_SortedAndDeduped(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "z.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(dir, "m.go"), []byte("package main"), 0644)

	cfg := config.Default()
	cfg.NoGit = true

	files, err := scanner.BuildFileList(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3", len(files))
	}
	for i := 1; i < len(files); i++ {
		if files[i] <= files[i-1] {
			t.Errorf("files not sorted: files[%d]=%q >= files[%d]=%q", i-1, files[i-1], i, files[i])
		}
	}
}

// Scan tests

func TestScanner_Scan_SingleFinding(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(
		filepath.Join(dir, "config.go"),
		[]byte("package main\n\nvar key = \"TESTKEY-ABCDEFGH\"\n"),
		0644,
	)

	cfg := config.Default()
	cfg.NoGit = true

	pats := []patterns.Pattern{testPattern(t)}
	ig := ignore.NewIgnorer(nil)
	s := scanner.New(cfg, pats, ig)

	found, summary, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1", len(found))
	}
	if summary.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", summary.FilesScanned)
	}
	if summary.FilesSkipped != 0 {
		t.Errorf("FilesSkipped = %d, want 0", summary.FilesSkipped)
	}
}

func TestScanner_Scan_NoFindings(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "clean.go"), []byte("package main\n\nfunc main() {}\n"), 0644)

	cfg := config.Default()
	cfg.NoGit = true

	s := scanner.New(cfg, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	found, _, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("got %d findings, want 0", len(found))
	}
}

func TestScanner_Scan_SkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	content := append([]byte("TESTKEY-ABCDEFGH"), 0x00)
	os.WriteFile(filepath.Join(dir, "binary.bin"), content, 0644)

	cfg := config.Default()
	cfg.NoGit = true

	s := scanner.New(cfg, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	found, summary, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("got %d findings, want 0", len(found))
	}
	if summary.FilesSkipped != 1 {
		t.Errorf("FilesSkipped = %d, want 1", summary.FilesSkipped)
	}
}

func TestScanner_Scan_SkipsOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	// Write a file slightly larger than the max we'll set.
	os.WriteFile(filepath.Join(dir, "big.go"), []byte("TESTKEY-ABCDEFGH\n"), 0644)

	cfg := config.Default()
	cfg.NoGit = true
	cfg.MaxFileSize = 5 // 5 bytes max — our file is larger

	s := scanner.New(cfg, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	found, summary, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("got %d findings, want 0", len(found))
	}
	if summary.FilesSkipped != 1 {
		t.Errorf("FilesSkipped = %d, want 1", summary.FilesSkipped)
	}
}

func TestScanner_Scan_SeverityFilter(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.go"), []byte("TESTKEY-ABCDEFGH\n"), 0644)

	cfg := config.Default()
	cfg.NoGit = true
	cfg.Severity = findings.Critical // testPattern is High — should be filtered out

	s := scanner.New(cfg, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	found, _, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("got %d findings (expected 0 after severity filter)", len(found))
	}
}

func TestScanner_Scan_SortedFindings(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "z.go"), []byte("TESTKEY-ABCDEFGH\n"), 0644)
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("TESTKEY-ABCDEFGH\n"), 0644)

	cfg := config.Default()
	cfg.NoGit = true

	s := scanner.New(cfg, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	found, _, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("got %d findings, want 2", len(found))
	}
	if found[0].File >= found[1].File {
		t.Errorf("findings not sorted: %q should come before %q", found[0].File, found[1].File)
	}
}

func TestScanner_Scan_SummaryCounts(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "match.go"), []byte("TESTKEY-ABCDEFGH\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.go"), []byte("nothing here\n"), 0644)
	// binary file — will be skipped
	os.WriteFile(filepath.Join(dir, "binary.bin"), append([]byte("data"), 0x00), 0644)

	cfg := config.Default()
	cfg.NoGit = true

	s := scanner.New(cfg, []patterns.Pattern{testPattern(t)}, ignore.NewIgnorer(nil))
	_, summary, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if summary.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2", summary.FilesScanned)
	}
	if summary.FilesSkipped != 1 {
		t.Errorf("FilesSkipped = %d, want 1", summary.FilesSkipped)
	}
}

func TestScanner_Scan_MultipleWorkers(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.go", "d.go", "e.go"} {
		os.WriteFile(filepath.Join(dir, name), []byte("TESTKEY-ABCDEFGH\n"), 0644)
	}

	pats := []patterns.Pattern{testPattern(t)}
	ig := ignore.NewIgnorer(nil)

	cfg1 := config.Default()
	cfg1.NoGit = true
	cfg1.Workers = 1

	cfg8 := config.Default()
	cfg8.NoGit = true
	cfg8.Workers = 8

	found1, _, err := scanner.New(cfg1, pats, ig).Scan(dir)
	if err != nil {
		t.Fatalf("Scan (1 worker): %v", err)
	}

	found8, _, err := scanner.New(cfg8, pats, ig).Scan(dir)
	if err != nil {
		t.Fatalf("Scan (8 workers): %v", err)
	}

	if !reflect.DeepEqual(found1, found8) {
		t.Errorf("results differ between 1 and 8 workers:\n1: %v\n8: %v", found1, found8)
	}
}
