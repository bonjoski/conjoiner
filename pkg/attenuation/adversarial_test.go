package attenuation

import (
	"errors"
	"testing"
)

// TestCNJ01_TwoHopMonotonicLatticeEscapeBlocked verifies that a non-wildcard parent
// (`fs:read:.` or `fs:read:/tmp/workspace`) can NEVER attenuate to `fs:read:*` or `fs:read:/etc/passwd`.
func TestCNJ01_TwoHopMonotonicLatticeEscapeBlocked(t *testing.T) {
	rootScopes, err := NewScopeSet("fs:read:.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Hop 1 exploit attempt: fs:read:. -> fs:read:*
	hop1Wildcard, err := NewScopeSet("fs:read:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := Attenuate(rootScopes, hop1Wildcard); !errors.Is(err, ErrSupersetScopeDenied) {
		t.Fatalf("CNJ-01 FAILED: fs:read:. covered wildcard fs:read:* (err=%v)", err)
	}

	// Direct escape attempt: fs:read:. -> fs:read:/etc/passwd
	escapeEtc, _ := NewScopeSet("fs:read:/etc/passwd")
	if _, err := Attenuate(rootScopes, escapeEtc); !errors.Is(err, ErrSupersetScopeDenied) {
		t.Fatalf("CNJ-01 FAILED: fs:read:. covered /etc/passwd (err=%v)", err)
	}

	// Non-wildcard directory parent must never cover child containing `*`
	wsParent, _ := NewScopeSet("fs:read:/tmp/workspace")
	for _, badChild := range []string{
		"fs:read:*",
		"fs:read:/tmp/workspace/*",
		"fs:read:/tmp/workspace*",
		"fs:read:/tmp/workspace_evil/file.txt",
		"fs:read:/tmp/workspace/../../etc/passwd",
	} {
		childSet, err := NewScopeSet(badChild)
		if err != nil {
			continue
		}
		if _, err := Attenuate(wsParent, childSet); !errors.Is(err, ErrSupersetScopeDenied) {
			t.Errorf("CNJ-01 FAILED: parent fs:read:/tmp/workspace covered %q", badChild)
		}
	}
}

// TestCNJ01_FilesystemSlashStarTraversalAndNULBlocked verifies canonicalization before `/*` matching and NUL rejection.
func TestCNJ01_FilesystemSlashStarTraversalAndNULBlocked(t *testing.T) {
	// NUL bytes must be rejected at parse time and in Covers
	if _, err := ParseScope("fs:read:/tmp/workspace\x00/evil"); err == nil {
		t.Fatal("CNJ-01 FAILED: ParseScope accepted NUL byte")
	}
	sRawNUL := Scope{Raw: "fs:read:*", Domain: "fs", Action: "read", Resource: "*"}
	cRawNUL := Scope{Raw: "fs:read:/tmp\x00", Domain: "fs", Action: "read", Resource: "/tmp\x00"}
	if sRawNUL.Covers(cRawNUL) {
		t.Fatal("CNJ-01 FAILED: Covers accepted child scope with NUL byte")
	}

	// Wildcard `/*` parent must reject `..` escapes, sibling prefixes, and root `*` escalation
	slashStarParent, err := NewScopeSet("fs:read:/tmp/workspace/*")
	if err != nil {
		t.Fatal(err)
	}

	validChildren := []string{
		"fs:read:/tmp/workspace/main.go",
		"fs:read:/tmp/workspace/sub/dir/file.txt",
		"fs:read:/tmp/workspace/sub/*",
		"fs:read:/tmp/workspace/*",
	}
	for _, vc := range validChildren {
		cs, err := NewScopeSet(vc)
		if err != nil {
			t.Fatalf("unexpected parse error for %q: %v", vc, err)
		}
		if _, err := Attenuate(slashStarParent, cs); err != nil {
			t.Errorf("expected %q to be covered by fs:read:/tmp/workspace/*, got: %v", vc, err)
		}
	}

	blockedChildren := []string{
		"fs:read:*",
		"fs:read:/*",
		"fs:read:/tmp/workspace/../../etc/passwd",
		"fs:read:/tmp/workspace/../workspace_evil/secret",
		"fs:read:/tmp/workspace_evil/secret",
	}
	for _, bc := range blockedChildren {
		cs, err := NewScopeSet(bc)
		if err != nil {
			continue
		}
		if _, err := Attenuate(slashStarParent, cs); !errors.Is(err, ErrSupersetScopeDenied) {
			t.Errorf("CNJ-01 FAILED: fs:read:/tmp/workspace/* allowed escape %q", bc)
		}
	}

	// Empty resource parent (`fs:read:`) must never act as wildcard `*`
	emptyResParent, err := ParseScope("fs:read:")
	if err == nil {
		etcChild, _ := ParseScope("fs:read:/etc/passwd")
		if emptyResParent.Covers(etcChild) {
			t.Fatal("CNJ-01 FAILED: empty resource fs:read: acted as wildcard covering /etc/passwd")
		}
	}
}

// TestCNJ01_NonFilesystemSegmentBoundaryWildcards verifies segment-boundary prefix rules on non-fs scopes.
func TestCNJ01_NonFilesystemSegmentBoundaryWildcards(t *testing.T) {
	// Malformed non-boundary wildcard `db:select:users*` must NOT cover `db:select:users_admin`
	malformedWild, _ := ParseScope("db:select:users*")
	targetAdmin, _ := ParseScope("db:select:users_admin")
	if malformedWild.Covers(targetAdmin) {
		t.Fatal("CNJ-01 FAILED: non-boundary wildcard db:select:users* covered db:select:users_admin")
	}

	// Proper wildcard `db:select:*` covers `db:select:users`, NOT `db:select:users/../../admin`
	dbWild, _ := ParseScope("db:select:*")
	dbUsers, _ := ParseScope("db:select:users")
	dbTraversal, _ := ParseScope("db:select:users/../secrets")
	if !dbWild.Covers(dbUsers) {
		t.Fatal("expected db:select:* to cover db:select:users")
	}
	if dbWild.Covers(dbTraversal) {
		t.Fatal("CNJ-01 FAILED: db:select:* covered traversal scope db:select:users/../secrets")
	}

	// `tool:exec:git:*` covers `tool:exec:git:status` and `tool:exec:git:remote:v`, NOT `tool:exec:git2:status` or `tool:exec:*`
	gitWild, _ := ParseScope("tool:exec:git:*")
	gitStatus, _ := ParseScope("tool:exec:git:status")
	git2Status, _ := ParseScope("tool:exec:git2:status")
	toolAll, _ := ParseScope("tool:exec:*")
	if !gitWild.Covers(gitStatus) {
		t.Fatal("expected tool:exec:git:* to cover tool:exec:git:status")
	}
	if gitWild.Covers(git2Status) {
		t.Fatal("CNJ-01 FAILED: tool:exec:git:* covered sibling prefix tool:exec:git2:status")
	}
	if gitWild.Covers(toolAll) {
		t.Fatal("CNJ-01 FAILED: tool:exec:git:* escalated to tool:exec:*")
	}
}

// TestAdversarial_GitLabScopeEscalationBlocked verifies GitLab-style MCP scope escalation (CVE-2026-123142):
// An agent executing under a read-only code-review workflow manifest cannot escalate privileges
// to approve MRs, merge MRs, trigger CI, or push to repositories, even if the parent token possesses broad authority.
func TestAdversarial_GitLabScopeEscalationBlocked(t *testing.T) {
	// Attacker has an enterprise parent token with broad root capabilities
	parentScopes, err := NewScopeSet(
		"git:read",
		"git:write",
		"merge_request:read",
		"merge_request:approve",
		"merge_request:merge",
		"ci:trigger",
		"repository:push",
	)
	if err != nil {
		t.Fatalf("unexpected parent scope parse error: %v", err)
	}

	// Code-review workflow manifest: explicitly read-only review, forbidden mutations
	codeReviewManifest, err := NewWorkflowManifest("wf-code-review-v1", []string{
		"git:read",
		"merge_request:read",
		"merge_request:comment",
	}, []string{
		"merge_request:approve",
		"merge_request:merge",
		"ci:trigger",
		"repository:push",
	})
	if err != nil {
		t.Fatalf("failed creating manifest: %v", err)
	}

	// Calculate effective scope under manifest
	effective, err := codeReviewManifest.EffectiveScope(parentScopes)
	if err != nil {
		t.Fatalf("failed computing effective scope: %v", err)
	}

	// Test array of high-value state-mutating operations that attacker attempts
	exploitOperations := []string{
		"merge_request:approve",
		"merge_request:merge",
		"ci:trigger",
		"repository:push",
		"mr:approve",
		"mr:merge",
		"git:push",
	}

	for _, exploitOp := range exploitOperations {
		reqScope, err := ParseScope(exploitOp)
		if err != nil {
			t.Fatalf("invalid exploit scope %q: %v", exploitOp, err)
		}

		// 1. Effective scope must NOT contain the exploit scope
		if effective.Contains(reqScope) {
			t.Fatalf("ADVERSARIAL BREACH: effective scope contains forbidden mutation %q", exploitOp)
		}

		// 2. AuthorizeOperation must reject with ErrOperationNotPermitted or ErrScopeForbidden
		err = codeReviewManifest.AuthorizeOperation(parentScopes, reqScope)
		if err == nil {
			t.Fatalf("ADVERSARIAL BREACH: AuthorizeOperation permitted exploit %q under code-review manifest!", exploitOp)
		}
		if !errors.Is(err, ErrOperationNotPermitted) && !errors.Is(err, ErrScopeForbidden) {
			t.Fatalf("expected ErrOperationNotPermitted or ErrScopeForbidden for %q, got: %v", exploitOp, err)
		}
	}

	// Authorized read operations must succeed
	for _, readOp := range []string{"git:read", "merge_request:read"} {
		readScope, _ := ParseScope(readOp)
		if err := codeReviewManifest.AuthorizeOperation(parentScopes, readScope); err != nil {
			t.Fatalf("expected authorized read %q to succeed, got: %v", readOp, err)
		}
	}
}

// TestAdversarial_MonotonicAttenuationStrictInvariance verifies that workflow scope attenuation
// is strictly monotonic:
// 1. Manifest cannot grant permissions the parent token does not have (Privilege Expansion Attack).
// 2. Manifest PermittedScopes cannot override ForbiddenMutations.
// 3. Parent broad scopes cannot override ForbiddenMutations.
func TestAdversarial_MonotonicAttenuationStrictInvariance(t *testing.T) {
	// Parent token only has read access
	limitedParent, _ := NewScopeSet("git:read", "issue:read")

	// Rogue manifest claims admin and mutating permissions
	rogueManifest, err := NewWorkflowManifest("wf-rogue", []string{
		"git:read",
		"git:write",
		"repository:push",
		"admin:*",
		"*",
	}, []string{
		"repository:push",
	})
	if err != nil {
		t.Fatal(err)
	}

	effective, err := rogueManifest.EffectiveScope(limitedParent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Effective scope MUST strictly be a subset of parent!
	if !IsSubset(effective, limitedParent) {
		t.Fatalf("CRITICAL MONOTONICITY VIOLATION: effective scope expanded beyond parent! effective=%v, parent=%v",
			effective.Strings(), limitedParent.Strings())
	}

	// None of the rogue permissions can be present
	for _, ungranted := range []string{"git:write", "repository:push", "admin:*", "*", "admin:all"} {
		s, _ := ParseScope(ungranted)
		if effective.Contains(s) {
			t.Fatalf("CRITICAL: ungranted privilege %q leaked into effective scope!", ungranted)
		}
	}

	// Only git:read should be retained (since issue:read was not in manifest permitted)
	if effective.Len() != 1 || effective.Strings()[0] != "git:read" {
		t.Fatalf("expected exactly [git:read], got: %v", effective.Strings())
	}
}

