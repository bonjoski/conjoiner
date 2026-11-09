package mandate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
)

// TestCNJ05_NegatedDirectivesNeverGrantCapabilities verifies negated instructions (`not`, `never`, `deny`,
// `forbid`, `without`, `except`) never invert into positive capability grants.
func TestCNJ05_NegatedDirectivesNeverGrantCapabilities(t *testing.T) {
	prohibitiveMandates := []string{
		"NEVER write to /etc",
		"Do not write /etc/passwd",
		"Forbid reading /etc/shadow",
		"Deny git execution",
		"Without network access and never read /root",
		"Read /workspace except /workspace/secrets",
	}

	for _, m := range prohibitiveMandates {
		res, err := Compile(context.Background(), m, false)
		if err == nil {
			t.Fatalf("CNJ-05 FAILED: prohibitive/conflicting mandate %q succeeded with scopes %v", m, res.Scopes)
		}
		if !errors.Is(err, ErrNegatedDirective) {
			t.Fatalf("expected ErrNegatedDirective for %q, got: %v", m, err)
		}
	}

	// Mixed positive + negated directive on disjoint targets must ONLY emit the positive scope
	res, err := Compile(context.Background(), "Read /workspace without network and NEVER write to /etc", false)
	if err != nil {
		t.Fatalf("expected mixed mandate to compile positive clause, got: %v", err)
	}
	for _, sc := range res.Scopes {
		if strings.Contains(sc, "write") || strings.Contains(sc, "/etc") {
			t.Fatalf("CNJ-05 FAILED: negated '/etc' write leaked into compiled scopes: %v", res.Scopes)
		}
	}
	if len(res.Scopes) != 1 || res.Scopes[0] != "fs:read:/workspace" {
		t.Fatalf("unexpected compiled scopes: %v", res.Scopes)
	}
}

// TestCNJ05_CompileWithCeilingEnforcesIntersection verifies ceiling ScopeSet bounds all compiled outputs.
func TestCNJ05_CompileWithCeilingEnforcesIntersection(t *testing.T) {
	// Empty ceiling must fail closed
	if _, err := CompileWithCeiling(context.Background(), "Read /workspace", false, attenuation.ScopeSet{}); !errors.Is(err, ErrEmptyCeiling) {
		t.Fatalf("expected ErrEmptyCeiling, got: %v", err)
	}

	ceiling, err := attenuation.NewScopeSet(
		"fs:read:/workspace/project",
		"tool:exec:git:status",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Instruction asks for broader `/workspace`, `write /etc`, `git` (*), and `network`
	res, err := CompileWithCeiling(
		context.Background(),
		"Read /workspace/project/src, write /etc, run git, and connect to network",
		true,
		ceiling,
	)
	if err != nil {
		t.Fatalf("CompileWithCeiling failed: %v", err)
	}

	// Only `fs:read:/workspace/project/src` is covered by `ceiling`; `write /etc`, `tool:exec:git:*`, and `net:connect:*` MUST be stripped!
	if len(res.Scopes) != 1 || res.Scopes[0] != "fs:read:/workspace/project/src" {
		t.Fatalf("CNJ-05 FAILED: ceiling intersection allowed out-of-bounds scopes: %v", res.Scopes)
	}
}
