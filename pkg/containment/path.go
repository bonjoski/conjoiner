package containment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrPathEscape indicates the requested path resolves outside the permitted workspace root.
	ErrPathEscape = errors.New("containment: path escapes repository confinement boundary")

	// ErrSymlinkTarget indicates a symlink resolves to a target outside the workspace root.
	ErrSymlinkTarget = errors.New("containment: symlink resolves outside repository confinement boundary")

	// ErrInvalidWorkspace indicates the provided workspace root is invalid.
	ErrInvalidWorkspace = errors.New("containment: invalid workspace root")
)

// InodeValidator enforces strict lexical and canonical filesystem confinement.
type InodeValidator interface {
	ValidatePath(workspaceRoot, requestedPath string) (string, error)
}

// StrictPathValidator implements InodeValidator using realpath and lexical prefix checks.
type StrictPathValidator struct{}

// NewStrictPathValidator constructs a thread-safe path containment validator.
func NewStrictPathValidator() *StrictPathValidator {
	return &StrictPathValidator{}
}

// ValidatePath verifies that requestedPath strictly resolves within workspaceRoot.
func (v *StrictPathValidator) ValidatePath(workspaceRoot, requestedPath string) (string, error) {
	if workspaceRoot == "" {
		return "", ErrInvalidWorkspace
	}

	cleanRoot := filepath.Clean(workspaceRoot)
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return "", fmt.Errorf("containment: unable to resolve workspace root: %w", err)
	}

	// Step 1: Lexical resolution & initial containment check
	targetPath := requestedPath
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(cleanRoot, targetPath)
	}
	targetPath = filepath.Clean(targetPath)

	relLexical, err := filepath.Rel(cleanRoot, targetPath)
	if err != nil || strings.HasPrefix(relLexical, "..") || relLexical == ".." {
		return "", ErrPathEscape
	}

	// Step 2: Traverse up to the nearest existing ancestor to resolve existing symlinks
	current := targetPath
	var nonExistentSuffix []string

	for {
		realCurrent, err := filepath.EvalSymlinks(current)
		if err == nil {
			// Ancestor exists: verify it is confined inside realRoot
			if !isSubdirectoryOrSame(realRoot, realCurrent) {
				return "", ErrSymlinkTarget
			}
			// Reconstruct canonical target with existing canonical ancestor
			if len(nonExistentSuffix) > 0 {
				for i := len(nonExistentSuffix) - 1; i >= 0; i-- {
					realCurrent = filepath.Join(realCurrent, nonExistentSuffix[i])
				}
			}
			targetPath = filepath.Clean(realCurrent)
			break
		}

		if errors.Is(err, os.ErrNotExist) {
			parent := filepath.Dir(current)
			if parent == current {
				// Reached root without finding existing directory
				return "", ErrPathEscape
			}
			nonExistentSuffix = append(nonExistentSuffix, filepath.Base(current))
			current = parent
			continue
		}

		return "", fmt.Errorf("containment: filesystem error during ancestor traversal: %w", err)
	}

	// Step 3: Final boundary assertion on fully resolved path
	rel, err := filepath.Rel(realRoot, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
		return "", ErrPathEscape
	}

	return targetPath, nil
}

func isSubdirectoryOrSame(root, target string) bool {
	if root == target {
		return true
	}
	prefix := root + string(filepath.Separator)
	return strings.HasPrefix(target, prefix)
}
