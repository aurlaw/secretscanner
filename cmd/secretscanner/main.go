package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/aurlaw/secretscanner/internal/config"
	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/ignore"
	"github.com/aurlaw/secretscanner/internal/output"
	"github.com/aurlaw/secretscanner/internal/scanner"
	"github.com/aurlaw/secretscanner/internal/version"
)

// flags holds raw CLI flag values before they are merged into Config.
// Keeping flags separate from Config prevents cobra from writing directly
// into the config struct, which keeps the two decoupled and testable.
type flags struct {
	workers     int
	maxFileSize string
	minFileSize string
	format      string
	severity    string
	noGit       bool
	noProgress  bool
	exitCode    bool
	include     []string
	exclude     []string
	configFile  string
	ignoreFile  string
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var f flags

	cmd := &cobra.Command{
		Use:     "secretscanner [directory]",
		Short:   "Scan a codebase for accidentally committed secrets",
		Version: fmt.Sprintf("%s (%s)", version.Version, version.Commit),
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, f, args)
		},
		SilenceUsage: true,
	}

	cmd.Flags().IntVar(&f.workers, "workers", 8, "number of concurrent scanning goroutines")
	cmd.Flags().StringVar(&f.maxFileSize, "max-file-size", "1MB", "skip files larger than this size")
	cmd.Flags().StringVar(&f.minFileSize, "min-size", "0", "skip files smaller than this size (0 = no minimum)")
	cmd.Flags().StringVar(&f.format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&f.severity, "severity", "low", "minimum severity to report: low, medium, high, critical")
	cmd.Flags().BoolVar(&f.noGit, "no-git", false, "disable git-aware mode, always use full directory walk")
	cmd.Flags().BoolVar(&f.noProgress, "no-progress", false, "suppress progress output on stderr")
	cmd.Flags().BoolVar(&f.exitCode, "exit-code", false, "exit with code 1 if findings exist")
	cmd.Flags().StringArrayVar(&f.include, "include", nil, "glob patterns for files to include")
	cmd.Flags().StringArrayVar(&f.exclude, "exclude", nil, "glob patterns for files to exclude")
	cmd.Flags().StringVar(&f.configFile, "config", ".secretscanner.yaml", "path to config file")
	cmd.Flags().StringVar(&f.ignoreFile, "ignore-file", ".secretsignore", "path to ignore file")

	return cmd
}

func run(cmd *cobra.Command, f flags, args []string) error {
	// 1. Resolve target directory.
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving directory: %w", err)
	}

	// 2. Load config file onto defaults.
	cfg, err := config.Load(f.configFile, config.Default())
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// 3. Apply CLI flag overrides — flags always win over config file.
	cfg.Workers = f.workers
	cfg.NoGit = f.noGit
	cfg.NoProgress = f.noProgress
	cfg.ExitCode = f.exitCode
	cfg.Format = f.format
	cfg.ConfigFile = f.configFile
	cfg.IgnoreFile = f.ignoreFile
	if f.include != nil {
		cfg.Include = f.include
	}
	if f.exclude != nil {
		cfg.Exclude = f.exclude
	}

	if f.maxFileSize != "" && f.maxFileSize != "0" {
		n, parseErr := humanize.ParseBytes(f.maxFileSize)
		if parseErr != nil {
			return fmt.Errorf("invalid --max-file-size %q: %w", f.maxFileSize, parseErr)
		}
		cfg.MaxFileSize = int64(n)
	}
	if f.minFileSize != "" && f.minFileSize != "0" {
		n, parseErr := humanize.ParseBytes(f.minFileSize)
		if parseErr != nil {
			return fmt.Errorf("invalid --min-size %q: %w", f.minFileSize, parseErr)
		}
		cfg.MinFileSize = int64(n)
	}

	sev, err := findings.ParseSeverity(f.severity)
	if err != nil {
		return fmt.Errorf("invalid --severity: %w", err)
	}
	cfg.Severity = sev

	// 4. Resolve patterns.
	pats, err := config.ResolvePatterns(cfg)
	if err != nil {
		return fmt.Errorf("resolving patterns: %w", err)
	}

	// 5. Parse ignore file.
	rules, err := ignore.Parse(cfg.IgnoreFile)
	if err != nil {
		return fmt.Errorf("loading ignore file: %w", err)
	}
	ignorer := ignore.NewIgnorer(rules)

	// 6. Start progress indicator.
	var progressDone chan struct{}
	if !cfg.NoProgress {
		progressDone = make(chan struct{})
		go startProgress(progressDone)
	}

	// 7. Run scan.
	s := scanner.New(cfg, pats, ignorer)
	found, summary, scanErr := s.Scan(absDir)

	// 8. Stop progress indicator before writing output.
	if progressDone != nil {
		close(progressDone)
		time.Sleep(50 * time.Millisecond)
	}

	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	// 9. Write output.
	switch cfg.Format {
	case "json":
		if err := output.WriteJSON(os.Stdout, found, summary); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	default:
		output.WriteText(os.Stdout, found, summary)
	}

	// 10. Exit code.
	if cfg.ExitCode && len(found) > 0 {
		os.Exit(1)
	}

	return nil
}

func startProgress(done <-chan struct{}) {
	frames := []string{"|", "/", "-", "\\"}
	i := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	defer fmt.Fprint(os.Stderr, "\r\033[K")

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			fmt.Fprintf(os.Stderr, "\r  %s  scanning...", frames[i%len(frames)])
			i++
		}
	}
}
