package main

import (
	"context"
	"strings"
	"testing"

	"github.com/bonjoski/conjoiner/pkg/mandate"
)

func TestMandateCompile_Integration(t *testing.T) {
	instruction := "Read /workspace and execute git status with AI review"
	res, err := mandate.Compile(context.Background(), instruction, true)
	if err != nil {
		t.Fatalf("mandate.Compile failed: %v", err)
	}

	if len(res.Scopes) == 0 {
		t.Fatalf("expected compiled scopes, got 0")
	}

	foundRead := false
	foundGit := false
	for _, s := range res.Scopes {
		if strings.HasPrefix(s, "fs:read") {
			foundRead = true
		}
		if strings.HasPrefix(s, "tool:exec:git") {
			foundGit = true
		}
	}

	if !foundRead {
		t.Errorf("expected fs:read scope in %v", res.Scopes)
	}
	if !foundGit {
		t.Errorf("expected tool:exec:git scope in %v", res.Scopes)
	}
	if res.Advisory == "" {
		t.Errorf("expected non-empty AI advisory")
	}
}
