package attenuation

import (
	"errors"
	"testing"
)

// TestAttenuationSubsetSuccess verifies that valid subset scope attenuation succeeds.
// Matches deliverable: test_attenuation_subset_success
func TestAttenuationSubsetSuccess(t *testing.T) {
	t.Run("test_attenuation_subset_success", func(t *testing.T) {
		parentScopes, err := NewScopeSet(
			"fs:read:/tmp/workspace",
			"tool:exec:git:*",
			"api:read:metrics",
		)
		if err != nil {
			t.Fatalf("failed to create parent scope set: %v", err)
		}

		requestedScopes, err := NewScopeSet(
			"fs:read:/tmp/workspace/src",
			"tool:exec:git:status",
		)
		if err != nil {
			t.Fatalf("failed to create requested scope set: %v", err)
		}

		attenuated, err := Attenuate(parentScopes, requestedScopes)
		if err != nil {
			t.Fatalf("expected attenuation to succeed, got error: %v", err)
		}

		if attenuated.Len() != 2 {
			t.Fatalf("expected 2 scopes in attenuated set, got %d", attenuated.Len())
		}

		if !attenuated.Contains(Scope{Domain: "fs", Action: "read", Resource: "/tmp/workspace/src"}) {
			t.Errorf("expected fs:read:/tmp/workspace/src to be in attenuated set")
		}

		if !attenuated.Contains(Scope{Domain: "tool", Action: "exec", Resource: "git:status"}) {
			t.Errorf("expected tool:exec:git:status to be in attenuated set")
		}
	})
}

// TestAttenuationSupersetDenied verifies that attempting to expand permissions beyond parent scope fails.
// Matches deliverable: test_attenuation_superset_denied
func TestAttenuationSupersetDenied(t *testing.T) {
	t.Run("test_attenuation_superset_denied", func(t *testing.T) {
		parentScopes, err := NewScopeSet(
			"fs:read:/tmp/workspace",
			"tool:exec:git:status",
		)
		if err != nil {
			t.Fatalf("failed to create parent scope set: %v", err)
		}

		// Test 1: Action escalation (read -> write)
		supersetAction, err := NewScopeSet(
			"fs:write:/tmp/workspace",
		)
		if err != nil {
			t.Fatalf("failed to create superset action set: %v", err)
		}

		_, err = Attenuate(parentScopes, supersetAction)
		if err == nil {
			t.Fatalf("expected error for write action escalation, got nil")
		}
		if !errors.Is(err, ErrSupersetScopeDenied) {
			t.Errorf("expected ErrSupersetScopeDenied, got %v", err)
		}

		// Test 2: Resource path escalation (escape to /etc)
		supersetPath, err := NewScopeSet(
			"fs:read:/etc/passwd",
		)
		if err != nil {
			t.Fatalf("failed to create superset path set: %v", err)
		}

		_, err = Attenuate(parentScopes, supersetPath)
		if err == nil {
			t.Fatalf("expected error for path breakout, got nil")
		}
		if !errors.Is(err, ErrSupersetScopeDenied) {
			t.Errorf("expected ErrSupersetScopeDenied, got %v", err)
		}

		// Test 3: Tool command escalation (status -> push)
		supersetTool, err := NewScopeSet(
			"tool:exec:git:push",
		)
		if err != nil {
			t.Fatalf("failed to create superset tool set: %v", err)
		}

		_, err = Attenuate(parentScopes, supersetTool)
		if err == nil {
			t.Fatalf("expected error for tool escalation, got nil")
		}
		if !errors.Is(err, ErrSupersetScopeDenied) {
			t.Errorf("expected ErrSupersetScopeDenied, got %v", err)
		}

		// Test 4: Completely new domain
		supersetDomain, err := NewScopeSet(
			"aws:s3:read:secret-bucket",
		)
		if err != nil {
			t.Fatalf("failed to create superset domain set: %v", err)
		}

		_, err = Attenuate(parentScopes, supersetDomain)
		if err == nil {
			t.Fatalf("expected error for domain escalation, got nil")
		}
		if !errors.Is(err, ErrSupersetScopeDenied) {
			t.Errorf("expected ErrSupersetScopeDenied, got %v", err)
		}
	})
}

func TestScopeIntersection(t *testing.T) {
	parent, _ := NewScopeSet(
		"fs:read:/tmp/workspace",
		"tool:exec:git:status",
	)

	requested, _ := NewScopeSet(
		"fs:read:/tmp/workspace/sub",
		"fs:write:/tmp/workspace", // Not in parent
		"tool:exec:git:status",
	)

	intersected := Intersect(parent, requested)
	if intersected.Len() != 2 {
		t.Fatalf("expected 2 intersecting scopes, got %d", intersected.Len())
	}

	strs := intersected.Strings()
	expected := []string{"fs:read:/tmp/workspace/sub", "tool:exec:git:status"}
	for i, exp := range expected {
		if strs[i] != exp {
			t.Errorf("expected %s at index %d, got %s", exp, i, strs[i])
		}
	}
}

func TestScopeParsingEdgeCases(t *testing.T) {
	_, err := ParseScope("")
	if !errors.Is(err, ErrEmptyScope) {
		t.Errorf("expected ErrEmptyScope, got %v", err)
	}

	_, err = ParseScope("singlepart")
	if !errors.Is(err, ErrInvalidScopeFormat) {
		t.Errorf("expected ErrInvalidScopeFormat, got %v", err)
	}

	wildcard, err := ParseScope("*")
	if err != nil {
		t.Fatalf("unexpected error parsing wildcard: %v", err)
	}
	if !wildcard.Covers(Scope{Raw: "anything:here:now", Domain: "anything", Action: "here", Resource: "now"}) {
		t.Errorf("wildcard scope must cover any other scope")
	}
}
