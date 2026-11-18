package agentpass

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/conjoiner/pkg/token"
)

func generateTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating test keys: %v", err)
	}
	return pub, priv
}

func TestIssueRootPass_Success(t *testing.T) {
	pub, priv := generateTestKeys(t)
	now := time.Now()

	opts := IssueOptions{
		AgentID:         "agent:orchestrator:01",
		HumanSupervisor: "benskolmoski@bonjo.dev",
		Scope:           []string{"repo:read", "repo:write", "git:commit"},
		SessionID:       "sess-test-123",
		WorktreePath:    "/Users/benskolmoski/code/spanreed",
		DPoPThumbprint:  "jkt_test_thumbprint_987",
		RequireHardware: true,
		Lifetime:        2 * time.Hour,
		TokenTTL:        30 * time.Second,
	}

	pass, signed, err := IssueRootPass(opts, priv, now)
	if err != nil {
		t.Fatalf("expected IssueRootPass success, got: %v", err)
	}

	if pass.HumanSupervisor != "benskolmoski@bonjo.dev" {
		t.Errorf("expected supervisor benskolmoski@bonjo.dev, got: %s", pass.HumanSupervisor)
	}
	if pass.DelegationDepth != 0 {
		t.Errorf("expected root delegation depth 0, got: %d", pass.DelegationDepth)
	}
	if pass.ExpiresAt != now.Add(2*time.Hour).Unix() {
		t.Errorf("expected expiration in 2h, got: %d", pass.ExpiresAt)
	}

	// Verify signed token
	verified, err := Verify(signed, pub, now)
	if err != nil {
		t.Fatalf("expected verification success, got: %v", err)
	}
	if verified.PassID != pass.PassID {
		t.Errorf("expected PassID %s, got %s", pass.PassID, verified.PassID)
	}
	if !verified.VerifyDPoPBinding("jkt_test_thumbprint_987") {
		t.Errorf("expected DPoP binding to match")
	}
}

func TestIssueRootPass_MissingSupervisor(t *testing.T) {
	_, priv := generateTestKeys(t)
	now := time.Now()

	opts := IssueOptions{
		AgentID:         "agent:headless",
		HumanSupervisor: "", // MISSING
		Scope:           []string{"repo:read"},
	}

	_, _, err := IssueRootPass(opts, priv, now)
	if err == nil || !strings.Contains(err.Error(), "human supervisor identity is required") {
		t.Fatalf("expected ErrUnauthorizedSupervisor, got: %v", err)
	}
}

func TestVerify_TamperingAndExpiration(t *testing.T) {
	pub, priv := generateTestKeys(t)
	now := time.Now()

	opts := IssueOptions{
		AgentID:         "agent:01",
		HumanSupervisor: "lead@bonjo.dev",
		Scope:           []string{"repo:read"},
		Lifetime:        10 * time.Minute,
	}

	_, signed, err := IssueRootPass(opts, priv, now)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// 1. Signature Tampering
	parts := strings.Split(signed, ".")
	tampered := parts[0] + "." + parts[1] + ".invalidSignatureBytes"
	_, err = Verify(tampered, pub, now)
	if err == nil {
		t.Errorf("expected signature verification failure for tampered token")
	}

	// 2. Expiration
	future := now.Add(15 * time.Minute)
	_, err = Verify(signed, pub, future)
	if err != ErrExpiredPass {
		t.Errorf("expected ErrExpiredPass, got: %v", err)
	}
}

func TestAttenuatePass_MonotonicSubset(t *testing.T) {
	pub, priv := generateTestKeys(t)
	now := time.Now()

	rootOpts := IssueOptions{
		AgentID:         "agent:orchestrator",
		HumanSupervisor: "dev@bonjo.dev",
		Scope:           []string{"repo:read", "repo:write", "git:commit", "git:push"},
		MaxDepth:        2,
	}

	rootPass, _, err := IssueRootPass(rootOpts, priv, now)
	if err != nil {
		t.Fatalf("setup root failed: %v", err)
	}

	// Derive Subagent 1 (Attenuated: Read + Commit only)
	childOpts := AttenuateOptions{
		RequestedScope: []string{"repo:read", "git:commit"},
		ChildAgentID:   "agent:worker:01",
		ChildDPoPThumb: "jkt_worker_01",
	}

	childPass, childSigned, err := AttenuatePass(rootPass, childOpts, priv, now)
	if err != nil {
		t.Fatalf("expected attenuation success, got: %v", err)
	}

	if childPass.DelegationDepth != 1 {
		t.Errorf("expected child depth 1, got: %d", childPass.DelegationDepth)
	}
	if childPass.ParentPassID != rootPass.PassID {
		t.Errorf("expected parent ID %s, got: %s", rootPass.PassID, childPass.ParentPassID)
	}

	// Verify child pass
	verifiedChild, err := Verify(childSigned, pub, now)
	if err != nil {
		t.Fatalf("failed child verification: %v", err)
	}
	if len(verifiedChild.Scope) != 2 {
		t.Errorf("expected 2 child scopes, got: %d", len(verifiedChild.Scope))
	}
}

func TestAttenuatePass_PrivilegeEscalationDenied(t *testing.T) {
	_, priv := generateTestKeys(t)
	now := time.Now()

	rootOpts := IssueOptions{
		AgentID:         "agent:orchestrator",
		HumanSupervisor: "dev@bonjo.dev",
		Scope:           []string{"repo:read", "git:status"},
	}

	rootPass, _, err := IssueRootPass(rootOpts, priv, now)
	if err != nil {
		t.Fatalf("setup root failed: %v", err)
	}

	// Subagent attempts to request un-granted "admin:delete" and "git:push"
	childOpts := AttenuateOptions{
		RequestedScope: []string{"repo:read", "git:push", "admin:delete"},
	}

	_, _, err = AttenuatePass(rootPass, childOpts, priv, now)
	if err == nil {
		t.Fatalf("expected privilege escalation failure, got nil")
	}
	if !strings.Contains(err.Error(), "superset permission expansion denied") {
		t.Errorf("expected superset permission expansion denied error, got: %v", err)
	}
}

func TestAttenuatePass_MaxDepthEnforcement(t *testing.T) {
	_, priv := generateTestKeys(t)
	now := time.Now()

	rootOpts := IssueOptions{
		AgentID:         "agent:root",
		HumanSupervisor: "dev@bonjo.dev",
		Scope:           []string{"repo:read"},
		MaxDepth:        1, // Max depth is 1
	}

	rootPass, _, err := IssueRootPass(rootOpts, priv, now)
	if err != nil {
		t.Fatalf("setup root failed: %v", err)
	}

	// Tier 1 (depth 1) -> Allowed
	child1, _, err := AttenuatePass(rootPass, AttenuateOptions{
		RequestedScope: []string{"repo:read"},
	}, priv, now)
	if err != nil {
		t.Fatalf("expected tier 1 success, got: %v", err)
	}

	// Tier 2 (depth 2) -> Exceeds max depth 1 -> Denied
	_, _, err = AttenuatePass(child1, AttenuateOptions{
		RequestedScope: []string{"repo:read"},
	}, priv, now)
	if err == nil || !strings.Contains(err.Error(), "maximum subagent delegation depth exceeded") {
		t.Fatalf("expected ErrMaxDelegationDepthExceeded, got: %v", err)
	}
}

func TestMintToolToken_AttenuatedAction(t *testing.T) {
	pub, priv := generateTestKeys(t)
	now := time.Now()

	passOpts := IssueOptions{
		AgentID:         "agent:coder",
		HumanSupervisor: "dev@bonjo.dev",
		Scope:           []string{"git:commit", "git:status"},
		TokenTTL:        30 * time.Second,
	}

	pass, _, err := IssueRootPass(passOpts, priv, now)
	if err != nil {
		t.Fatalf("setup pass failed: %v", err)
	}

	// 1. Allowed action: "git:commit"
	tok, signedTok, err := MintToolToken(pass, "git:commit", priv, now)
	if err != nil {
		t.Fatalf("expected MintToolToken success, got: %v", err)
	}

	if tok.ExpiresAt != now.Add(30*time.Second).Unix() {
		t.Errorf("expected 30s TTL, got exp: %d", tok.ExpiresAt)
	}

	// Parse and verify signed JWT using token package
	parsedTok, err := token.ParseAndVerifyToken(signedTok, pub, now)
	if err != nil {
		t.Fatalf("failed verifying minted token: %v", err)
	}
	if parsedTok.Subject != pass.AgentID {
		t.Errorf("expected subject %s, got: %s", pass.AgentID, parsedTok.Subject)
	}

	// 2. Denied out-of-scope action: "aws:s3:delete"
	_, _, err = MintToolToken(pass, "aws:s3:delete", priv, now)
	if err == nil {
		t.Fatalf("expected error for ungranted action, got nil")
	}
	if !strings.Contains(err.Error(), "action 'aws:s3:delete' is not covered") {
		t.Errorf("expected action not covered error, got: %v", err)
	}
}

func TestHardwareGate_AmortizedLease(t *testing.T) {
	os.Setenv("CONJOINER_MOCK_BIOMETRIC", "approved")
	defer os.Unsetenv("CONJOINER_MOCK_BIOMETRIC")

	gate := NewHardwareGate()
	gate.SetLeaseTTL(1 * time.Minute)

	pass := &AgentPass{
		AgentID:         "agent:sub:01",
		SessionID:       "sess-amortized-99",
		HumanSupervisor: "dev@bonjo.dev",
		RequireHardware: true,
	}

	ctx := context.Background()

	// 1. First elevation for mutating action: prompts/evaluates mock -> grants lease
	err := gate.CheckAndAuthorize(ctx, pass, "git:push")
	if err != nil {
		t.Fatalf("expected initial authorization success, got: %v", err)
	}

	// 2. Disable mock to simulate environment where prompt is NOT triggered again
	os.Setenv("CONJOINER_MOCK_BIOMETRIC", "denied")

	// 3. Second call within TTL from sibling subagent in the same session
	siblingPass := &AgentPass{
		AgentID:         "agent:sub:02",
		SessionID:       "sess-amortized-99", // Same session
		HumanSupervisor: "dev@bonjo.dev",
		RequireHardware: true,
	}

	err = gate.CheckAndAuthorize(ctx, siblingPass, "git:push")
	if err != nil {
		t.Fatalf("expected amortized lease hit without prompting, got: %v", err)
	}

	// 4. Foreign session without active lease -> Denied by mock
	foreignPass := &AgentPass{
		AgentID:         "agent:foreign:01",
		SessionID:       "sess-different-44",
		HumanSupervisor: "other@bonjo.dev",
		RequireHardware: true,
	}

	err = gate.CheckAndAuthorize(ctx, foreignPass, "git:push")
	if err == nil {
		t.Fatalf("expected foreign session without lease to be challenged/denied")
	}
}
