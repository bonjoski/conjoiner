package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/conjoiner/pkg/mandate"
	"github.com/bonjoski/conjoiner/pkg/mcp"
	"github.com/bonjoski/conjoiner/pkg/token"
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

func TestMCPShimCommand_PresenceAndManifestFlags(t *testing.T) {
	// Verify mcp-shim accepts --require-hardware-presence and --target-command
	// We test by configuring a dry-run invocation with invalid command
	tmpDir := t.TempDir()
	manifestPath := tmpDir + "/test_manifest.json"
	manifestContent := `{"workflow_id":"test","permitted_scopes":["tool:exec:ok"]}`
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := mcp.Config{
		TargetCommand:           "/bin/echo",
		AllowedScopes:           []string{"tool:exec:ok"},
		RequireHardwarePresence: true,
		WorkflowManifestPath:    manifestPath,
	}

	shim, err := mcp.NewTransportShim(cfg)
	if err != nil {
		t.Fatalf("failed initializing shim with CLI config: %v", err)
	}
	if shim == nil {
		t.Fatal("expected non-nil shim")
	}
}

// TestEndToEndLifecycle_ZeroBackgroundWorkloadIdentityWorkflowScopeSanitizer validates the full
// end-to-end lifecycle under RFC-2026-11-17-37:
// 1. Workload identity minting with unique UUID JTI, SPIFFE subject, DPoP binding, and 30s TTL.
// 2. Zero-Background-Authority hardware presence gating (unprompted background calls fail closed while locked).
// 3. Workflow-bound scope attenuation (blocking unauthorized state mutations like MR approve).
// 4. Outbound Shield finding secret sanitization ([REDACTED_SECRET]) and JTI trace injection.
// 5. Instant sub-minute JTI revocation (subsequent calls fail closed immediately).
func TestEndToEndLifecycle_ZeroBackgroundWorkloadIdentityWorkflowScopeSanitizer(t *testing.T) {
	tmpDir := t.TempDir()
	auditLogPath := filepath.Join(tmpDir, "audit.log")
	manifestPath := filepath.Join(tmpDir, "code_review_manifest.json")

	// Step 1: Workload Identity Minting with JTI
	brokerPub, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating broker keypair: %v", err)
	}

	dpopKey, err := token.GenerateDPoPKey()
	if err != nil {
		t.Fatalf("failed generating dpop key: %v", err)
	}

	sessionID := "e2e-session-78a1bc"
	grantedScopes := []string{
		"git:read",
		"tool:exec:security_scan",
		"merge_request:read",
		"merge_request:approve",
		"ci:trigger",
	}

	tok, tokenJWT, err := token.MintWorkloadIdentity(sessionID, dpopKey.PublicKey, grantedScopes, brokerPriv)
	if err != nil {
		t.Fatalf("failed minting workload identity: %v", err)
	}

	if tok.Subject != "spiffe://bonjo.dev/agent/"+sessionID {
		t.Fatalf("unexpected SPIFFE subject: %s", tok.Subject)
	}
	if len(tok.JTI) != 36 || tok.JTI[14] != '4' {
		t.Fatalf("unexpected JTI UUID format: %s", tok.JTI)
	}
	if time.Duration(tok.ExpiresAt-tok.IssuedAt)*time.Second != token.DefaultTTL {
		t.Fatalf("expected 30s TTL, got %d seconds", tok.ExpiresAt-tok.IssuedAt)
	}
	if !tok.VerifyDPoPBinding(dpopKey.Thumbprint()) {
		t.Fatal("DPoP key confirmation thumbprint binding failed")
	}

	// Step 2 & 3 Setup: Write workflow manifest forbidding mutations
	manifestContent := `{
		"workflow_id": "wf-code-review-v1",
		"permitted_scopes": [
			"git:read",
			"tool:exec:security_scan",
			"merge_request:read"
		],
		"forbidden_mutations": [
			"merge_request:approve",
			"ci:trigger",
			"repository:push"
		]
	}`
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0600); err != nil {
		t.Fatalf("failed writing manifest: %v", err)
	}

	revStore := token.NewMemoryRevocationStore()
	cfg := mcp.Config{
		TargetCommand:           "/bin/cat",
		Token:                   tokenJWT,
		BrokerPubKey:            brokerPub,
		RequireHardwarePresence: true,
		WorkflowManifestPath:    manifestPath,
		ScrubSecrets:            true,
		AuditLogPath:            auditLogPath,
		SessionID:               sessionID,
		RevocationStore:         revStore,
	}

	shim, err := mcp.NewTransportShim(cfg)
	if err != nil {
		t.Fatalf("failed constructing transport shim: %v", err)
	}

	// Step 2: Zero-Background Hardware Presence Gating
	t.Setenv("MOCK_LOCK_STATE", "locked")

	scanCall := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"security_scan","arguments":{}}}`
	var serverIn, clientOut bytes.Buffer
	if shim.HandleInboundLine([]byte(scanCall), &serverIn, &clientOut) {
		t.Fatal("expected unattended call to be blocked while workstation locked")
	}

	var lockErrResp mcp.JSONRPCMessage
	if err := json.Unmarshal(clientOut.Bytes(), &lockErrResp); err != nil {
		t.Fatalf("failed parsing lock error: %v", err)
	}
	if lockErrResp.Error == nil || lockErrResp.Error.Code != mcp.ErrCodePolicyViolation {
		t.Fatalf("expected ErrCodePolicyViolation (-32001), got: %+v", lockErrResp.Error)
	}

	// Verify audit log recorded the blocked background attempt
	auditData, err := os.ReadFile(auditLogPath)
	if err != nil || !strings.Contains(string(auditData), "security_scan") {
		t.Fatalf("expected blocked presence call recorded in audit log: %s", string(auditData))
	}

	// Step 3: Workstation unlocked -> Workflow Manifest Mutation Gating
	t.Setenv("MOCK_LOCK_STATE", "unlocked")

	// Attempt unauthorized state mutation (merge_request:approve)
	approveCall := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"merge_request:approve","arguments":{"mr_id":42}}}`
	serverIn.Reset()
	clientOut.Reset()
	if shim.HandleInboundLine([]byte(approveCall), &serverIn, &clientOut) {
		t.Fatal("expected state mutation merge_request:approve to be blocked by workflow manifest")
	}

	var approveErrResp mcp.JSONRPCMessage
	if err := json.Unmarshal(clientOut.Bytes(), &approveErrResp); err != nil {
		t.Fatalf("failed parsing approve error: %v", err)
	}
	if approveErrResp.Error == nil || approveErrResp.Error.Code != mcp.ErrCodeScopeDenied {
		t.Fatalf("expected ErrCodeScopeDenied (-32002), got: %+v", approveErrResp.Error)
	}

	// Step 4: Authorized execution -> Outbound Shield Finding Secret Scrubbing & JTI trace injection
	serverIn.Reset()
	clientOut.Reset()
	if !shim.HandleInboundLine([]byte(scanCall), &serverIn, &clientOut) {
		t.Fatalf("expected authorized scanCall to be permitted: %s", clientOut.String())
	}

	respObj := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"findings": []string{
				"GitLab token leaked: glpat-abcdef1234567890xyza",
				"GitHub token leaked: ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
				"Slack token leaked: xoxb-mock-token-sample-123456",
				"SSH Private Key: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----",
			},
		},
	}
	rawDownstreamResponse, err := json.Marshal(respObj)
	if err != nil {
		t.Fatalf("failed marshaling downstream response: %v", err)
	}

	outbound := shim.HandleOutboundLine(rawDownstreamResponse)
	outboundStr := string(outbound)

	// Verify all raw secrets are scrubbed
	leakedPatterns := []string{
		"glpat-abcdef1234567890xyza",
		"ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
		"xoxb-mock-token-sample-123456",
		"BEGIN OPENSSH PRIVATE KEY",
	}
	for _, p := range leakedPatterns {
		if strings.Contains(outboundStr, p) {
			t.Fatalf("raw secret leaked in outbound response: %s (in: %s)", p, outboundStr)
		}
	}

	if !strings.Contains(outboundStr, "[REDACTED_SECRET]") {
		t.Fatalf("expected [REDACTED_SECRET] in sanitized output, got: %s", outboundStr)
	}

	t.Logf("outbound: %s", outboundStr)

	// Verify JTI trace correlation in _meta
	if !strings.Contains(outboundStr, tok.JTI) {
		t.Fatalf("expected correlation JTI %s in outbound response metadata: %s", tok.JTI, outboundStr)
	}

	// Step 5: Sub-minute JTI Revocation
	if err := revStore.RevokeWithReason(tok.JTI, time.Now().Add(24*time.Hour), "emergency tripwire revocation"); err != nil {
		t.Fatalf("RevokeWithReason failed: %v", err)
	}

	// Any subsequent tool call with the revoked token must fail closed
	clientOut.Reset()
	subsequentCall := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"security_scan","arguments":{}}}`
	if shim.HandleInboundLine([]byte(subsequentCall), &serverIn, &clientOut) {
		t.Fatal("expected tool call to be rejected after JTI revocation!")
	}

	var revokeErrResp mcp.JSONRPCMessage
	if err := json.Unmarshal(clientOut.Bytes(), &revokeErrResp); err != nil {
		t.Fatalf("failed parsing revoke error: %v", err)
	}
	if revokeErrResp.Error == nil || revokeErrResp.Error.Code != mcp.ErrCodePolicyViolation {
		t.Fatalf("expected ErrCodePolicyViolation (-32001) on revoked token, got: %+v", revokeErrResp.Error)
	}
}

