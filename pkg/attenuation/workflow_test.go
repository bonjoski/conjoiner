package attenuation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkflowManifest_EffectiveScopeCalculation(t *testing.T) {
	manifestJSON := []byte(`{
		"workflow_id": "wf_code_review_v1",
		"permitted_scopes": [
			"git:read",
			"issue:read",
			"merge_request:read",
			"merge_request:comment"
		],
		"forbidden_mutations": [
			"merge_request:approve",
			"merge_request:merge",
			"repository:push",
			"ci:trigger"
		]
	}`)

	wm, err := ParseWorkflowManifest(manifestJSON)
	if err != nil {
		t.Fatalf("failed parsing workflow manifest: %v", err)
	}

	// Case 1: Broad parent token ("*")
	rootParent, _ := NewScopeSet("*")
	effective, err := wm.EffectiveScope(rootParent)
	if err != nil {
		t.Fatalf("unexpected error computing effective scope: %v", err)
	}

	// Effective scope should match permitted scopes exactly (4 scopes)
	if effective.Len() != 4 {
		t.Fatalf("expected 4 effective scopes, got %d: %v", effective.Len(), effective.Strings())
	}
	for _, expected := range []string{"git:read", "issue:read", "merge_request:read", "merge_request:comment"} {
		s, _ := ParseScope(expected)
		if !effective.Contains(s) {
			t.Errorf("expected effective scope to contain %q", expected)
		}
	}

	// Forbidden mutations must NOT be present
	for _, forbidden := range []string{"merge_request:approve", "merge_request:merge", "repository:push", "ci:trigger"} {
		s, _ := ParseScope(forbidden)
		if effective.Contains(s) {
			t.Errorf("forbidden mutation %q leaked into effective scope", forbidden)
		}
	}

	// Case 2: Parent only has subset: "git:read", "merge_request:read", "merge_request:approve"
	subsetParent, _ := NewScopeSet("git:read", "merge_request:read", "merge_request:approve")
	effectiveSubset, err := wm.EffectiveScope(subsetParent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Effective scope = subsetParent ∩ Permitted \ Forbidden
	// "issue:read" and "merge_request:comment" are stripped because parent lacks them
	// "merge_request:approve" is stripped because manifest does not permit it AND lists it as forbidden
	if effectiveSubset.Len() != 2 {
		t.Fatalf("expected 2 effective scopes, got %d: %v", effectiveSubset.Len(), effectiveSubset.Strings())
	}
	sGitRead, _ := ParseScope("git:read")
	sMRRead, _ := ParseScope("merge_request:read")
	if !effectiveSubset.Contains(sGitRead) || !effectiveSubset.Contains(sMRRead) {
		t.Errorf("expected git:read and merge_request:read in effective subset: %v", effectiveSubset.Strings())
	}
}

func TestWorkflowManifest_AuthorizeOperation_Gating(t *testing.T) {
	wm, err := NewWorkflowManifest("wf-review", []string{
		"git:read",
		"merge_request:read",
	}, []string{
		"merge_request:approve",
		"merge_request:merge",
		"ci:trigger",
		"repository:push",
	})
	if err != nil {
		t.Fatalf("failed creating manifest: %v", err)
	}

	// Parent has wide permissions including mutating ones
	parent, _ := NewScopeSet("git:read", "git:write", "merge_request:read", "merge_request:approve", "repository:push")

	// Authorized read
	mrRead, _ := ParseScope("merge_request:read")
	if err := wm.AuthorizeOperation(parent, mrRead); err != nil {
		t.Fatalf("expected authorized operation, got: %v", err)
	}

	// Attempting mutating operation: merge_request:approve -> must fail closed with ErrScopeForbidden or ErrOperationNotPermitted
	mrApprove, _ := ParseScope("merge_request:approve")
	err = wm.AuthorizeOperation(parent, mrApprove)
	if err == nil {
		t.Fatal("expected merge_request:approve to be blocked, but it was authorized!")
	}
	if !errors.Is(err, ErrScopeForbidden) && !errors.Is(err, ErrOperationNotPermitted) {
		t.Fatalf("expected ErrScopeForbidden or ErrOperationNotPermitted, got: %v", err)
	}

	// Attempting mutating operation: repository:push -> must fail closed
	repoPush, _ := ParseScope("repository:push")
	err = wm.AuthorizeOperation(parent, repoPush)
	if err == nil {
		t.Fatal("expected repository:push to be blocked, but it was authorized!")
	}

	// Attempting unpermitted read: issue:read (not mutating, but not in permitted) -> ErrScopeForbidden
	issueRead, _ := ParseScope("issue:read")
	err = wm.AuthorizeOperation(parent, issueRead)
	if !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("expected ErrScopeForbidden for issue:read, got: %v", err)
	}
}

func TestWorkflowManifest_LoadFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	manifestFile := filepath.Join(tmpDir, "manifest.json")
	content := `{
		"workflow_id": "test-file-wf",
		"permitted_scopes": ["tool:exec:git:status", "tool:exec:git:diff"],
		"forbidden_mutations": ["tool:exec:git:push"]
	}`
	if err := os.WriteFile(manifestFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadWorkflowManifest(manifestFile)
	if err != nil {
		t.Fatalf("failed loading workflow manifest from file: %v", err)
	}
	if loaded.WorkflowID != "test-file-wf" {
		t.Fatalf("expected workflow ID 'test-file-wf', got %q", loaded.WorkflowID)
	}
	if len(loaded.PermittedScopes) != 2 {
		t.Fatalf("expected 2 permitted scopes, got %d", len(loaded.PermittedScopes))
	}
}

func TestWorkflowManifest_EmptyValidation(t *testing.T) {
	if _, err := NewWorkflowManifest("", []string{"git:read"}, nil); !errors.Is(err, ErrEmptyManifest) {
		t.Fatalf("expected ErrEmptyManifest on empty ID, got: %v", err)
	}
	if _, err := NewWorkflowManifest("id", nil, nil); !errors.Is(err, ErrEmptyManifest) {
		t.Fatalf("expected ErrEmptyManifest on empty scopes, got: %v", err)
	}
}
