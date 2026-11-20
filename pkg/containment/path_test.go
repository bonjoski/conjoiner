package containment

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStrictPathValidator(t *testing.T) {
	// Setup temporary directory structure for tests
	tmpDir := t.TempDir()
	realTmp, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("Failed to resolve real tempdir: %v", err)
	}

	workspace := filepath.Join(realTmp, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, "src", "sub"), 0755); err != nil {
		t.Fatalf("Failed to create workspace layout: %v", err)
	}

	// Create an existing file
	mainGo := filepath.Join(workspace, "src", "main.go")
	if err := os.WriteFile(mainGo, []byte("package main"), 0644); err != nil {
		t.Fatalf("Failed to create main.go: %v", err)
	}

	// Create outside sensitive directory and file
	outsideDir := filepath.Join(realTmp, "outside")
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatalf("Failed to create outside dir: %v", err)
	}
	secretFile := filepath.Join(outsideDir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("SUPERSECRET"), 0600); err != nil {
		t.Fatalf("Failed to create secret.key: %v", err)
	}

	// Create symlink inside workspace pointing inside workspace
	insideSymlink := filepath.Join(workspace, "src", "link_inside")
	if err := os.Symlink(filepath.Join(workspace, "src", "sub"), insideSymlink); err != nil {
		t.Fatalf("Failed to create internal symlink: %v", err)
	}

	// Create symlink inside workspace pointing outside workspace
	outsideSymlink := filepath.Join(workspace, "src", "link_outside")
	if err := os.Symlink(outsideDir, outsideSymlink); err != nil {
		t.Fatalf("Failed to create escape symlink: %v", err)
	}

	validator := NewStrictPathValidator()

	tests := []struct {
		name          string
		workspace     string
		requested     string
		expectError   error
		expectExact   string
		expectSuccess bool
	}{
		{
			name:          "Valid relative file",
			workspace:     workspace,
			requested:     "src/main.go",
			expectSuccess: true,
			expectExact:   mainGo,
		},
		{
			name:          "Valid absolute file inside workspace",
			workspace:     workspace,
			requested:     mainGo,
			expectSuccess: true,
			expectExact:   mainGo,
		},
		{
			name:          "Lexical traversal escape (../../outside/secret.key)",
			workspace:     workspace,
			requested:     "../../outside/secret.key",
			expectSuccess: false,
			expectError:   ErrPathEscape,
		},
		{
			name:          "Valid internal symlink traversal",
			workspace:     workspace,
			requested:     "src/link_inside/test.txt",
			expectSuccess: true,
			expectExact:   filepath.Join(workspace, "src", "sub", "test.txt"),
		},
		{
			name:          "Escaping symlink traversal (GHSA-w42c-h7hr-f67p vector)",
			workspace:     workspace,
			requested:     "src/link_outside/secret.key",
			expectSuccess: false,
			expectError:   ErrSymlinkTarget,
		},
		{
			name:          "Non-existent file in valid subfolder",
			workspace:     workspace,
			requested:     "src/sub/nonexistent.txt",
			expectSuccess: true,
			expectExact:   filepath.Join(workspace, "src", "sub", "nonexistent.txt"),
		},
		{
			name:          "Non-existent deeply nested path in valid subfolder",
			workspace:     workspace,
			requested:     "src/sub/deep/nested/file.txt",
			expectSuccess: true,
			expectExact:   filepath.Join(workspace, "src", "sub", "deep", "nested", "file.txt"),
		},
		{
			name:          "Empty workspace root",
			workspace:     "",
			requested:     "src/main.go",
			expectSuccess: false,
			expectError:   ErrInvalidWorkspace,
		},
		{
			name:          "Sibling folder prefix collision (e.g. /workspace-fake vs /workspace)",
			workspace:     workspace,
			requested:     workspace + "-fake/hacked.txt",
			expectSuccess: false,
			expectError:   ErrPathEscape,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validator.ValidatePath(tt.workspace, tt.requested)
			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if tt.expectExact != "" && got != tt.expectExact {
					t.Errorf("expected exact path %q, got %q", tt.expectExact, got)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %v, got nil (returned: %q)", tt.expectError, got)
				}
				if tt.expectError != nil && !errors.Is(err, tt.expectError) {
					t.Errorf("expected error %v, got %v", tt.expectError, err)
				}
			}
		})
	}
}

// TestStrictPathValidator_ConcurrencyStress tests N=8 concurrent agents validating paths
func TestStrictPathValidator_ConcurrencyStress(t *testing.T) {
	tmpDir := t.TempDir()
	workspace := filepath.Join(tmpDir, "repo")
	if err := os.MkdirAll(filepath.Join(workspace, "pkg"), 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	validator := NewStrictPathValidator()
	var wg sync.WaitGroup
	const subagentCount = 8

	for i := 0; i < subagentCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 100; iter++ {
				validPath := filepath.Join("pkg", "file.go")
				if _, err := validator.ValidatePath(workspace, validPath); err != nil {
					t.Errorf("worker %d failed valid path: %v", id, err)
				}
				escapePath := "../../etc/passwd"
				if _, err := validator.ValidatePath(workspace, escapePath); !errors.Is(err, ErrPathEscape) {
					t.Errorf("worker %d failed to reject escape path: %v", id, err)
				}
			}
		}(i)
	}

	wg.Wait()
}
