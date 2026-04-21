package config

import (
	"fmt"
	"os"

	humanize "github.com/dustin/go-humanize"
	"gopkg.in/yaml.v3"

	"github.com/aurlaw/secretscanner/internal/findings"
	"github.com/aurlaw/secretscanner/internal/patterns"
)

// PatternConfig holds per-config-file pattern customisation.
type PatternConfig struct {
	Disable []string              // pattern names to remove from the built-in set
	Add     []patterns.RawPattern // additional custom patterns to compile and append
}

// Config holds the resolved runtime configuration for a scan.
// Fields are populated from defaults, then YAML, then CLI flags —
// later sources always win.
type Config struct {
	Workers     int
	MaxFileSize int64 // bytes; 0 means no limit
	MinFileSize int64 // bytes; 0 means no minimum
	Format      string
	Severity    findings.Severity
	NoGit       bool
	NoProgress  bool
	ExitCode    bool
	Include     []string
	Exclude     []string
	ConfigFile  string // path to .secretscanner.yaml; set from CLI flag only
	IgnoreFile  string // path to .secretsignore; set from CLI flag only
	Patterns    PatternConfig
}

// Default returns a Config with sensible out-of-the-box values.
func Default() Config {
	return Config{
		Workers:     8,
		MaxFileSize: 1 << 20,
		MinFileSize: 0,
		Format:      "text",
		Severity:    findings.Low,
		NoGit:       false,
		NoProgress:  false,
		ExitCode:    false,
		Include:     nil,
		Exclude:     nil,
		ConfigFile:  ".secretscanner.yaml",
		IgnoreFile:  ".secretsignore",
		Patterns:    PatternConfig{},
	}
}

// yamlFile is the intermediate struct used for YAML unmarshalling.
// Pointer fields allow distinguishing "absent" from "zero value".
type yamlFile struct {
	Settings *yamlSettings  `yaml:"settings"`
	Patterns *yamlPatterns  `yaml:"patterns"`
}

type yamlSettings struct {
	Workers     *int     `yaml:"workers"`
	MaxFileSize *string  `yaml:"max-file-size"`
	MinFileSize *string  `yaml:"min-size"`
	Format      *string  `yaml:"format"`
	Severity    *string  `yaml:"severity"`
	NoGit       *bool    `yaml:"no-git"`
	NoProgress  *bool    `yaml:"no-progress"`
	ExitCode    *bool    `yaml:"exit-code"`
	Include     []string `yaml:"include"`
	Exclude     []string `yaml:"exclude"`
}

type yamlPatterns struct {
	Disable []string              `yaml:"disable"`
	Add     []patterns.RawPattern `yaml:"add"`
}

// Load reads a YAML config file at path and merges its values onto base.
// If path does not exist, base is returned unchanged with a nil error.
func Load(path string, base Config) (Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return base, nil
	}
	if err != nil {
		return base, fmt.Errorf("config: load: %w", err)
	}

	var yf yamlFile
	if err := yaml.Unmarshal(data, &yf); err != nil {
		return base, fmt.Errorf("config: load: %w", err)
	}

	cfg := base

	if s := yf.Settings; s != nil {
		if s.Workers != nil {
			cfg.Workers = *s.Workers
		}
		if s.MaxFileSize != nil {
			n, err := humanize.ParseBytes(*s.MaxFileSize)
			if err != nil {
				return base, fmt.Errorf("config: load: max-file-size: %w", err)
			}
			cfg.MaxFileSize = int64(n)
		}
		if s.MinFileSize != nil {
			n, err := humanize.ParseBytes(*s.MinFileSize)
			if err != nil {
				return base, fmt.Errorf("config: load: min-size: %w", err)
			}
			cfg.MinFileSize = int64(n)
		}
		if s.Format != nil {
			cfg.Format = *s.Format
		}
		if s.Severity != nil {
			sev, err := findings.ParseSeverity(*s.Severity)
			if err != nil {
				return base, fmt.Errorf("config: load: severity: %w", err)
			}
			cfg.Severity = sev
		}
		if s.NoGit != nil {
			cfg.NoGit = *s.NoGit
		}
		if s.NoProgress != nil {
			cfg.NoProgress = *s.NoProgress
		}
		if s.ExitCode != nil {
			cfg.ExitCode = *s.ExitCode
		}
		if s.Include != nil {
			cfg.Include = s.Include
		}
		if s.Exclude != nil {
			cfg.Exclude = s.Exclude
		}
	}

	if p := yf.Patterns; p != nil {
		if p.Disable != nil {
			cfg.Patterns.Disable = p.Disable
		}
		if p.Add != nil {
			cfg.Patterns.Add = p.Add
		}
	}

	return cfg, nil
}

// ResolvePatterns builds the final pattern set for a scan by starting with
// the built-in patterns, removing any disabled by name, and appending custom ones.
func ResolvePatterns(cfg Config) ([]patterns.Pattern, error) {
	builtins := patterns.BuiltinPatterns()
	result := make([]patterns.Pattern, len(builtins))
	copy(result, builtins)

	if len(cfg.Patterns.Disable) > 0 {
		disabled := make(map[string]bool, len(cfg.Patterns.Disable))
		for _, name := range cfg.Patterns.Disable {
			disabled[name] = true
		}
		kept := result[:0]
		for _, p := range result {
			if !disabled[p.Name] {
				kept = append(kept, p)
			}
		}
		result = kept
	}

	for _, raw := range cfg.Patterns.Add {
		p, err := patterns.Compile(raw)
		if err != nil {
			return nil, fmt.Errorf("config: resolve patterns: %w", err)
		}
		result = append(result, p)
	}

	return result, nil
}
