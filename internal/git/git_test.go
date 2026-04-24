package git_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aurlaw/secretscanner/internal/git"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available in PATH")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no .git found)")
		}
		dir = parent
	}
}

// IsGitRepo tests

func TestIsGitRepo_WithGitDir(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if !git.IsGitRepo(dir) {
		t.Error("expected IsGitRepo to return true for dir with .git")
	}
}

func TestIsGitRepo_WithoutGitDir(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	if git.IsGitRepo(dir) {
		t.Error("expected IsGitRepo to return false for dir without .git")
	}
}

func TestIsGitRepo_NonExistentPath(t *testing.T) {
	requireGit(t)
	if git.IsGitRepo("/tmp/does-not-exist-secretscanner-test") {
		t.Error("expected IsGitRepo to return false for non-existent path")
	}
}

// ListFiles tests

func TestListFiles_ReturnsFiles(t *testing.T) {
	requireGit(t)
	root := repoRoot(t)
	files, err := git.ListFiles(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) == 0 {
		t.Error("expected at least one file, got none")
	}
}

func TestListFiles_AbsolutePaths(t *testing.T) {
	requireGit(t)
	root := repoRoot(t)
	files, err := git.ListFiles(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range files {
		if !filepath.IsAbs(f) {
			t.Errorf("path %q is not absolute", f)
		}
	}
}

func TestListFiles_NonGitDir(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	_, err := git.ListFiles(dir)
	if err == nil {
		t.Error("expected error for non-git directory, got nil")
	}
}
