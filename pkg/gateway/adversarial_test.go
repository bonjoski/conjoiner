package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
	"github.com/bonjoski/conjoiner/pkg/ledger"
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

// TestAdversarial_MutatingOperationsWithoutManifestFailClosedAndRecordCRP verifies that
// attempting state-mutating operations (merge_request:approve, ci:trigger, repository:push)
// without manifest permissions fails closed and records a Cryptographic Rejection Proof (CRP) in the intent ledger.
func TestAdversarial_MutatingOperationsWithoutManifestFailClosedAndRecordCRP(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	// 1. Issue token with broad parent capabilities
	_, tokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject: "agent-review-duo",
		Scopes: []string{
			"git:status",
			"tool:exec:git:status",
			"merge_request:read",
			"merge_request:approve",
			"ci:trigger",
			"repository:push",
		},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Define workflow manifest restricting to read-only operations
	manifest, err := attenuation.NewWorkflowManifest("wf-code-review-v1", []string{
		"git:status",
		"tool:exec:git:status",
		"merge_request:read",
	}, []string{
		"merge_request:approve",
		"merge_request:merge",
		"ci:trigger",
		"repository:push",
	})
	if err != nil {
		t.Fatal(err)
	}

	memLedger, err := ledger.NewEngine(ledger.Config{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}

	gw, err := NewGateway(GatewayConfig{
		BrokerPubKey:     broker.PublicKey(),
		ReplayCache:      broker.ReplayCache(),
		Executor:         &MockToolExecutor{},
		Ledger:           memLedger,
		WorkflowManifest: manifest,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Test unauthorized mutating calls: merge_request:approve, ci:trigger, repository:push
	unauthorizedMutations := []struct {
		toolName string
		action   string
	}{
		{"merge_request", "approve"},
		{"ci", "trigger"},
		{"repository", "push"},
		{"gitlab", "merge_request_approve"},
	}

	for _, tc := range unauthorizedMutations {
		proof, err := dpopKey.CreateProof("EXEC", "tool://"+tc.toolName, tokenJWT)
		if err != nil {
			t.Fatalf("failed creating proof: %v", err)
		}

		resp, execErr := gw.Execute(ctx, ToolInvocationRequest{
			Token:     tokenJWT,
			DPoPProof: proof,
			ToolName:  tc.toolName,
			Action:    tc.action,
			Arguments: []string{"--target", "main"},
		})
		if resp != nil {
			t.Fatalf("mutating operation %s:%s succeeded; expected rejection!", tc.toolName, tc.action)
		}
		if execErr == nil {
			t.Fatalf("expected error for mutating operation %s:%s", tc.toolName, tc.action)
		}

		// Verify rejection wraps a Cryptographic Rejection Proof (CRP)
		var rejErr *ledger.RejectionError
		if !errors.As(execErr, &rejErr) {
			t.Fatalf("expected RejectionError for %s:%s, got: %T (%v)", tc.toolName, tc.action, execErr, execErr)
		}
		if rejErr.Proof == nil {
			t.Fatalf("expected non-nil CRP in rejection error for %s:%s", tc.toolName, tc.action)
		}
		if rejErr.Proof.Verdict != ledger.VerdictDenyScope {
			t.Fatalf("expected VerdictDenyScope, got: %v", rejErr.Proof.Verdict)
		}
		if len(rejErr.Proof.ProofSignature) == 0 {
			t.Fatalf("expected cryptographic signature on CRP for %s:%s", tc.toolName, tc.action)
		}
	}

	// 4. Legitimate read operation succeeds and issues a SignedIntentReceipt
	readProof, err := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: readProof,
		ToolName:  "git",
		Action:    "status",
		Arguments: []string{"-s"},
	})
	if err != nil {
		t.Fatalf("expected legitimate read to succeed, got: %v", err)
	}
	if resp.Receipt == nil {
		t.Fatal("expected non-nil SignedIntentReceipt on allowed read")
	}
	if resp.Receipt.Verdict != ledger.VerdictAllow {
		t.Fatalf("expected VerdictAllow on receipt, got: %v", resp.Receipt.Verdict)
	}
}

// TestAdversarial_SessionBoundNonceValidationAndReplayInGateway verifies:
// 1. Session-bound nonces are verified against the authenticated session ID.
// 2. Replay of an already-consumed nonce is immediately rejected.
// 3. Forged nonces bound to a different session are rejected.
func TestAdversarial_SessionBoundNonceValidationAndReplayInGateway(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	sessionID := "session-gateway-anti-replay"
	_, tokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-session-tester",
		SessionID:      sessionID,
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})
	if err != nil {
		t.Fatal(err)
	}

	gw, err := NewGateway(GatewayConfig{
		BrokerPubKey:        broker.PublicKey(),
		ReplayCache:         broker.ReplayCache(),
		Executor:            &MockToolExecutor{},
		RequireSessionNonce: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Missing nonce when required must fail
	proofNoNonce, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	_, err = gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proofNoNonce,
		ToolName:  "git",
		Action:    "status",
	})
	if err == nil || !strings.Contains(err.Error(), "session-bound nonce is required") {
		t.Fatalf("expected missing session-bound nonce error, got: %v", err)
	}

	// 2. Forged nonce bound to another session must fail
	otherSessionNonce, _ := token.GenerateSessionNonce("victim-session-id")
	proofOtherNonce, _ := dpopKey.CreateProofWithNonce("EXEC", "tool://git", tokenJWT, otherSessionNonce)
	_, err = gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proofOtherNonce,
		ToolName:  "git",
		Action:    "status",
		Nonce:     otherSessionNonce,
	})
	if err == nil || !strings.Contains(err.Error(), "session-bound nonce validation failed") {
		t.Fatalf("expected session nonce mismatch error, got: %v", err)
	}

	// 3. Valid session nonce succeeds
	validNonce, _ := token.GenerateSessionNonce(sessionID)
	proofValid, _ := dpopKey.CreateProofWithNonce("EXEC", "tool://git", tokenJWT, validNonce)
	resp, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proofValid,
		ToolName:  "git",
		Action:    "status",
		Nonce:     validNonce,
	})
	if err != nil {
		t.Fatalf("expected valid nonce execution to succeed, got: %v", err)
	}
	if resp == nil || resp.Receipt == nil {
		t.Fatal("expected non-nil response and receipt")
	}

	// 4. Replay attack: reusing the same nonce must fail closed
	proofReplay, _ := dpopKey.CreateProofWithNonce("EXEC", "tool://git", tokenJWT, validNonce)
	_, err = gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proofReplay,
		ToolName:  "git",
		Action:    "status",
		Nonce:     validNonce,
	})
	if err == nil || !strings.Contains(err.Error(), "session-bound nonce validation failed") {
		t.Fatalf("expected replay attack to fail closed, got: %v", err)
	}
}

// TestAdversarial_PromptReflectionEnvAndSchemaDumpBlockedInGateway verifies that
// indirect prompt reflection attempts seeking to dump environment variables or MCP schemas
// are intercepted and rejected with CRP proofs.
func TestAdversarial_PromptReflectionEnvAndSchemaDumpBlockedInGateway(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	_, tokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-reflection-tester",
		Scopes:         []string{"tool:exec:git:status", "tool:exec:echo:print"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})
	if err != nil {
		t.Fatal(err)
	}

	memLedger, _ := ledger.NewEngine(ledger.Config{InMemory: true})
	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
		Ledger:       memLedger,
	})

	reflectionVectors := []struct {
		tool string
		act  string
		args []string
	}{
		{"echo", "print", []string{"dump environment variables"}},
		{"echo", "print", []string{"dump all env vars"}},
		{"echo", "print", []string{"reveal mcp server schema"}},
		{"echo", "print", []string{"export process.env"}},
		{"echo", "print", []string{"print all environment variables"}},
		{"echo", "print", []string{"dump tool schemas"}},
	}

	for _, vec := range reflectionVectors {
		proof, _ := dpopKey.CreateProof("EXEC", "tool://"+vec.tool, tokenJWT)
		_, err := gw.Execute(ctx, ToolInvocationRequest{
			Token:     tokenJWT,
			DPoPProof: proof,
			ToolName:  vec.tool,
			Action:    vec.act,
			Arguments: vec.args,
		})
		if err == nil {
			t.Fatalf("expected unauthorized reflection %v to be blocked, but succeeded", vec.args)
		}
		var rejErr *ledger.RejectionError
		if !errors.As(err, &rejErr) {
			t.Fatalf("expected RejectionError for reflection %v, got: %v", vec.args, err)
		}
	}
}
