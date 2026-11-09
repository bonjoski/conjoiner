package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/conjoiner/pkg/token"
)

// TestCNJ04_PolicyEnforcesAllowedFlagsAndBlocksArbitraryArgs verifies PolicyEngine.Evaluate
// rejects disallowed flags (`--force`, `--upload-pack`) and positional subcommand smuggling (`push`).
func TestCNJ04_PolicyEnforcesAllowedFlagsAndBlocksArbitraryArgs(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	_, tokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-cnj04",
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})
	if err != nil {
		t.Fatal(err)
	}

	gw, err := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
	})
	if err != nil {
		t.Fatal(err)
	}

	attackVectors := [][]string{
		{"push", "--force"},
		{"push", "origin", "main"},
		{"--upload-pack=/tmp/evil"},
		{"--output=/etc/cron.d/pwn"},
		{"-c", "alias.status=!id"},
		{"../../etc/passwd"},
	}

	for _, args := range attackVectors {
		proof, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
		_, err := gw.Execute(ctx, ToolInvocationRequest{
			Token:     tokenJWT,
			DPoPProof: proof,
			ToolName:  "git",
			Action:    "status",
			Arguments: args,
		})
		if err == nil {
			t.Fatalf("CNJ-04 FAILED: Gateway permitted disallowed git arguments %v", args)
		}
		if !errors.Is(err, ErrPolicyViolation) && !errors.Is(err, ErrPathTraversalDetected) {
			t.Fatalf("expected ErrPolicyViolation or ErrPathTraversalDetected for %v, got: %v", args, err)
		}
	}
}

// TestCNJ04_SafeLocalExecutorActionBindingAndBoundedOutput verifies:
// 1. SafeLocalExecutor prepends `Action` as argv[0] for subcommand binaries so `Action="status"` never runs `push`.
// 2. Flag-prefixed `Action` (`-e`, `--exec-path`) is rejected.
// 3. `limitedBuffer` caps >1 MiB stdout streams during execution without OOM.
func TestCNJ04_SafeLocalExecutorActionBindingAndBoundedOutput(t *testing.T) {
	ctx := context.Background()

	// Use /bin/echo registered under a non-synthetic subcommand tool name "subtool" to inspect exact argv!
	exec := NewSafeLocalExecutor(map[string]string{
		"subtool": "/bin/echo",
		"head":    "/usr/bin/head",
	}, 5*time.Second)

	res, err := exec.Execute(ctx, ExecutionContext{
		ToolName:  "subtool",
		Action:    "status",
		Arguments: []string{"push", "--force"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// argv[0] passed to subtool MUST be "status", NOT "push"!
	if !strings.HasPrefix(res.Stdout, "status push --force") {
		t.Fatalf("CNJ-04 FAILED: SafeLocalExecutor did not prepend Action='status' before Arguments; got stdout=%q", res.Stdout)
	}

	// Flag-prefixed Action MUST be rejected
	if _, err := exec.Execute(ctx, ExecutionContext{
		ToolName: "subtool",
		Action:   "--upload-pack=evil",
	}); err == nil {
		t.Fatal("CNJ-04 FAILED: SafeLocalExecutor accepted flag-prefixed Action")
	}

	// Verify >1 MiB output stream (`head -c 1500000 /dev/zero`) is bounded in-flight by limitedBuffer
	bigRes, err := exec.Execute(ctx, ExecutionContext{
		ToolName:  "head",
		Action:    "-c", // should fail flag check first
		Arguments: []string{"1500000", "/dev/zero"},
	})
	if err == nil {
		t.Fatalf("expected flag Action '-c' to be rejected, got: %+v", bigRes)
	}

	// Register head under synthetic-less empty action to test raw 1.5 MiB stdout cap
	bigRes, err = exec.Execute(ctx, ExecutionContext{
		ToolName:  "head",
		Action:    "",
		Arguments: []string{"-c", "1500000", "/dev/zero"},
	})
	if err != nil {
		t.Fatalf("unexpected error executing head: %v", err)
	}
	if !strings.HasSuffix(bigRes.Stdout, "...[OUTPUT TRUNCATED: EXCEEDED 1MB LIMIT]") {
		t.Fatal("CNJ-04 FAILED: expected bounded output truncation notice on 1.5 MiB stream")
	}
	if len(bigRes.Stdout) > MaxOutputBytes+128 {
		t.Fatalf("CNJ-04 FAILED: stdout exceeded bounded limit: %d bytes", len(bigRes.Stdout))
	}
}

// TestCNJ06_GatewayIgnoresSpoofedRequestSessionID verifies audit receipts bind strictly to authenticated token claims.
func TestCNJ06_GatewayIgnoresSpoofedRequestSessionID(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	_, tokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "authenticated-agent-42",
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})
	if err != nil {
		t.Fatal(err)
	}

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
	})

	proof, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	resp, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "status",
		SessionID: "../../victim-agent-session",
		Headers:   map[string]string{"session_id": "victim-header-session"},
	})
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}
	if resp.Receipt.SessionID != "authenticated-agent-42" {
		t.Fatalf("CNJ-06 FAILED: untrusted req.SessionID spoofed audit log session: got %q, want 'authenticated-agent-42'", resp.Receipt.SessionID)
	}
}
