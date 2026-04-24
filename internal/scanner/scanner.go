package scanner

import (
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/aurlaw/secretscanner/internal/config"
	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/git"
	"github.com/aurlaw/secretscanner/internal/ignore"
	"github.com/aurlaw/secretscanner/internal/patterns"
)

// BuildFileList returns the sorted, deduplicated list of files to scan in dir.
// It uses git ls-files when the directory is a git repo (unless cfg.NoGit),
// falling back silently to a full directory walk on git errors.
func BuildFileList(dir string, cfg config.Config) ([]string, error) {
	var raw []string

	if !cfg.NoGit && git.IsGitRepo(dir) {
		listed, err := git.ListFiles(dir)
		if err == nil {
			raw = listed
		}
	}

	if raw == nil {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type().IsRegular() {
				raw = append(raw, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// Apply include filter (match against base name).
	if len(cfg.Include) > 0 {
		kept := raw[:0]
		for _, path := range raw {
			base := filepath.Base(path)
			for _, glob := range cfg.Include {
				if matched, _ := filepath.Match(glob, base); matched {
					kept = append(kept, path)
					break
				}
			}
		}
		raw = kept
	}

	// Apply exclude filter (match against base name).
	if len(cfg.Exclude) > 0 {
		kept := raw[:0]
		for _, path := range raw {
			base := filepath.Base(path)
			excluded := false
			for _, glob := range cfg.Exclude {
				if matched, _ := filepath.Match(glob, base); matched {
					excluded = true
					break
				}
			}
			if !excluded {
				kept = append(kept, path)
			}
		}
		raw = kept
	}

	// Deduplicate.
	seen := make(map[string]struct{}, len(raw))
	deduped := raw[:0]
	for _, path := range raw {
		if _, ok := seen[path]; !ok {
			seen[path] = struct{}{}
			deduped = append(deduped, path)
		}
	}

	sort.Strings(deduped)
	return deduped, nil
}

// ScanSummary holds aggregate statistics for a completed scan.
type ScanSummary struct {
	FilesScanned int
	FilesSkipped int
	Elapsed      time.Duration
}

// Scanner orchestrates a concurrent secret scan over a directory tree.
type Scanner struct {
	cfg     config.Config
	pats    []patterns.Pattern
	ignorer ignore.Ignorer
}

// New creates a Scanner with the provided configuration, compiled patterns,
// and ignore rules.
func New(cfg config.Config, pats []patterns.Pattern, ignorer ignore.Ignorer) *Scanner {
	return &Scanner{cfg: cfg, pats: pats, ignorer: ignorer}
}

type scanResult struct {
	findings []findings.Finding
	skipped  bool
}

// processFile performs per-file checks and sends exactly one scanResult.
func (s *Scanner) processFile(path string, results chan<- scanResult) {
	ok, err := WithinSizeLimit(path, s.cfg.MinFileSize, s.cfg.MaxFileSize)
	if err != nil || !ok {
		results <- scanResult{skipped: true}
		return
	}

	binary, err := IsBinary(path)
	if err != nil || binary {
		results <- scanResult{skipped: true}
		return
	}

	found, err := ScanLines(path, s.pats, s.ignorer)
	if err != nil {
		results <- scanResult{skipped: true}
		return
	}

	results <- scanResult{findings: found}
}

// Scan runs a concurrent scan of dir and returns all findings, a summary, and
// any fatal error encountered while building the file list.
func (s *Scanner) Scan(dir string) ([]findings.Finding, ScanSummary, error) {
	start := time.Now()

	files, err := BuildFileList(dir, s.cfg)
	if err != nil {
		return nil, ScanSummary{}, err
	}

	jobs := make(chan string)
	results := make(chan scanResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				s.processFile(path, results)
			}
		}()
	}

	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []findings.Finding
	summary := ScanSummary{}
	for r := range results {
		if r.skipped {
			summary.FilesSkipped++
		} else {
			summary.FilesScanned++
			allFindings = append(allFindings, r.findings...)
		}
	}

	filtered := make([]findings.Finding, 0, len(allFindings))
	for _, f := range allFindings {
		if f.Severity >= s.cfg.Severity {
			filtered = append(filtered, f)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].File != filtered[j].File {
			return filtered[i].File < filtered[j].File
		}
		return filtered[i].Line < filtered[j].Line
	})

	summary.Elapsed = time.Since(start)
	return filtered, summary, nil
}
