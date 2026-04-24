package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IsGitRepo returns true if dir contains a .git entry.
// Any stat failure (missing, permission denied) is treated as "not a git repo".
func IsGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// ListFiles runs git ls-files in dir and returns absolute paths for all files
// git knows about (tracked and untracked, respecting .gitignore).
func ListFiles(dir string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git: ls-files in %q: %w", dir, err)
	}

	lines := strings.Split(string(out), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		paths = append(paths, filepath.Join(dir, line))
	}
	return paths, nil
}
