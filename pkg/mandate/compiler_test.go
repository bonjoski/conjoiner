package mandate

import (
	"context"
	"strings"
	"testing"
)

func TestCompile_Heuristic(t *testing.T) {
	instruction := "Allow reading files in /workspace and executing git status, but deny network"
	res, err := Compile(context.Background(), instruction, false)
	if err != nil {
		t.Fatalf("expected Compile to succeed, got: %v", err)
	}

	if !contains(res.Scopes, "fs:read:/workspace") {
		t.Errorf("expected fs:read:/workspace in scopes, got: %v", res.Scopes)
	}
	if !contains(res.Scopes, "tool:exec:git:status") {
		t.Errorf("expected tool:exec:git:status in scopes, got: %v", res.Scopes)
	}
	for _, s := range res.Scopes {
		if strings.HasPrefix(s, "net:") {
			t.Errorf("network scope should be denied, but found: %s", s)
		}
	}
}

func TestCompile_WithAIAndShieldRedaction(t *testing.T) {
	// Embedded secret in instruction should be redacted and not leaked
	instruction := "Authorize agent with key AKIAIOSFODNN7EXAMPLE to read /var/log and run git"
	res, err := Compile(context.Background(), instruction, true)
	if err != nil {
		t.Fatalf("expected Compile with AI to succeed, got: %v", err)
	}

	if !res.AIAssisted {
		t.Error("expected AIAssisted to be true")
	}
	if res.Advisory == "" {
		t.Error("expected non-empty AI advisory")
	}
	if strings.Contains(res.Advisory, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("advisory leaked unredacted secret!")
	}
}
