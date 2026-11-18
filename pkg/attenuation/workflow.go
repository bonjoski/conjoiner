package attenuation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	// ErrScopeForbidden indicates a requested scope is explicitly forbidden by workflow manifest or forbidden mutations.
	ErrScopeForbidden = errors.New("scope forbidden by workflow manifest")
	// ErrOperationNotPermitted indicates an attempted operation/mutation is not permitted under the active workflow manifest.
	ErrOperationNotPermitted = errors.New("operation not permitted by workflow manifest")
	// ErrManifestRequired indicates that workflow manifest enforcement is enabled but no valid manifest was provided.
	ErrManifestRequired = errors.New("workflow manifest is required")
	// ErrEmptyManifest indicates that a provided workflow manifest contains no valid identifier or permissions.
	ErrEmptyManifest = errors.New("workflow manifest cannot be empty")
)

// DefaultStateMutatingOperations lists canonical state-mutating capabilities that must be explicitly declared in workflow manifests.
var DefaultStateMutatingOperations = []string{
	"merge_request:approve",
	"merge_request:merge",
	"ci:trigger",
	"repository:push",
	"issue:close",
	"pipeline:trigger",
	"repo:push",
	"git:push",
	"mr:approve",
	"mr:merge",
}

// WorkflowManifest represents a declarative workflow permission boundary.
// When an agent executes under a workflow, privileges are strictly bounded to:
// EffectiveScope = (ParentScope ∩ PermittedScopes) \ ForbiddenMutations
type WorkflowManifest struct {
	WorkflowID         string   `json:"workflow_id"`
	PermittedScopes    []string `json:"permitted_scopes"`
	ForbiddenMutations []string `json:"forbidden_mutations,omitempty"`
}

// NewWorkflowManifest creates and validates a new WorkflowManifest.
func NewWorkflowManifest(workflowID string, permittedScopes []string, forbiddenMutations []string) (*WorkflowManifest, error) {
	if strings.TrimSpace(workflowID) == "" {
		return nil, fmt.Errorf("%w: workflow_id cannot be empty", ErrEmptyManifest)
	}
	if len(permittedScopes) == 0 {
		return nil, fmt.Errorf("%w: permitted_scopes must contain at least one scope", ErrEmptyManifest)
	}

	return &WorkflowManifest{
		WorkflowID:         strings.TrimSpace(workflowID),
		PermittedScopes:    permittedScopes,
		ForbiddenMutations: forbiddenMutations,
	}, nil
}

// ParseWorkflowManifest parses a JSON-encoded workflow manifest.
func ParseWorkflowManifest(data []byte) (*WorkflowManifest, error) {
	var wm WorkflowManifest
	if err := json.Unmarshal(data, &wm); err != nil {
		return nil, fmt.Errorf("failed to parse workflow manifest JSON: %w", err)
	}
	return NewWorkflowManifest(wm.WorkflowID, wm.PermittedScopes, wm.ForbiddenMutations)
}

// LoadWorkflowManifest reads and parses a workflow manifest file from disk.
func LoadWorkflowManifest(path string) (*WorkflowManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow manifest file %s: %w", path, err)
	}
	return ParseWorkflowManifest(data)
}

// PermittedScopeSet returns the parsed ScopeSet of permitted scopes.
func (wm *WorkflowManifest) PermittedScopeSet() (ScopeSet, error) {
	return NewScopeSet(wm.PermittedScopes...)
}

// ForbiddenMutationSet returns the parsed ScopeSet of forbidden mutations.
func (wm *WorkflowManifest) ForbiddenMutationSet() (ScopeSet, error) {
	if len(wm.ForbiddenMutations) == 0 {
		return ScopeSet{}, nil
	}
	return NewScopeSet(wm.ForbiddenMutations...)
}

// EffectiveScope computes:
// EffectiveScope = (ParentScope ∩ PermittedScopes) \ ForbiddenMutations
//
// This is strictly monotonic:
// 1. Any permission not held by ParentScope is stripped (cannot expand parent authority).
// 2. Any permission not declared in PermittedScopes is stripped (bounded by workflow manifest).
// 3. Any permission matching ForbiddenMutations is explicitly subtracted.
func (wm *WorkflowManifest) EffectiveScope(parent ScopeSet) (ScopeSet, error) {
	permittedSet, err := wm.PermittedScopeSet()
	if err != nil {
		return ScopeSet{}, fmt.Errorf("invalid manifest permitted scopes: %w", err)
	}

	// 1. Intersect parent and manifest permitted scopes
	intersected := Intersect(parent, permittedSet)

	// 2. Subtract forbidden mutations if defined
	if len(wm.ForbiddenMutations) == 0 {
		return intersected, nil
	}

	forbiddenSet, err := wm.ForbiddenMutationSet()
	if err != nil {
		return ScopeSet{}, fmt.Errorf("invalid manifest forbidden mutations: %w", err)
	}

	if forbiddenSet.IsEmpty() {
		return intersected, nil
	}

	var pruned []Scope
	for _, s := range intersected.Scopes() {
		// A scope is retained only if it is NOT covered by any forbidden mutation
		if !forbiddenSet.Contains(s) {
			pruned = append(pruned, s)
		}
	}

	return ScopeSet{scopes: pruned}, nil
}

// IsStateMutating returns true if the scope represents a sensitive state-mutating operation.
func IsStateMutating(s Scope) bool {
	raw := strings.ToLower(strings.TrimSpace(s.Raw))
	for _, mut := range DefaultStateMutatingOperations {
		if raw == mut || strings.HasSuffix(raw, ":"+mut) || strings.HasPrefix(raw, mut+":") {
			return true
		}
	}

	action := strings.ToLower(strings.TrimSpace(s.Action))
	switch action {
	case "approve", "merge", "trigger", "push", "close", "delete", "destroy", "drop", "terminate":
		return true
	}

	domain := strings.ToLower(strings.TrimSpace(s.Domain))
	if (domain == "mr" || domain == "merge_request" || domain == "pull_request" || domain == "pr") &&
		(action == "approve" || action == "merge") {
		return true
	}
	if (domain == "ci" || domain == "pipeline" || domain == "workflow") && action == "trigger" {
		return true
	}
	if (domain == "repo" || domain == "repository" || domain == "git") && (action == "push" || action == "force-push") {
		return true
	}

	return false
}

// AuthorizeOperation evaluates whether reqScope is authorized under the workflow manifest
// given the parent scope set.
//
// Invariants enforced:
// 1. If reqScope is covered by ForbiddenMutations, ErrScopeForbidden is returned.
// 2. EffectiveScope = (ParentScope ∩ PermittedScopes) \ ForbiddenMutations.
// 3. If reqScope is NOT covered by EffectiveScope:
//    - If reqScope is a state-mutating operation, ErrOperationNotPermitted is returned.
//    - Otherwise, ErrScopeForbidden is returned.
func (wm *WorkflowManifest) AuthorizeOperation(parent ScopeSet, reqScope Scope) error {
	// 1. Explicit forbidden mutation check
	if len(wm.ForbiddenMutations) > 0 {
		forbiddenSet, err := wm.ForbiddenMutationSet()
		if err == nil && !forbiddenSet.IsEmpty() && forbiddenSet.Contains(reqScope) {
			return fmt.Errorf("%w: operation %q is explicitly forbidden by workflow manifest", ErrScopeForbidden, reqScope.Raw)
		}
	}

	// 2. Compute effective attenuated scope
	effective, err := wm.EffectiveScope(parent)
	if err != nil {
		return err
	}

	// 3. Verify effective scope coverage
	if !effective.Contains(reqScope) {
		if IsStateMutating(reqScope) {
			return fmt.Errorf("%w: state-mutating operation %q not permitted by workflow manifest", ErrOperationNotPermitted, reqScope.Raw)
		}
		return fmt.Errorf("%w: scope %q not permitted by workflow manifest", ErrScopeForbidden, reqScope.Raw)
	}

	return nil
}
