package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPresence_MockLockStateEvaluation(t *testing.T) {
	checker := NewDefaultPresenceChecker()

	// 1. Locked mock state
	t.Setenv("MOCK_LOCK_STATE", "locked")
	err := checker.CheckPresence(context.Background())
	if err == nil {
		t.Fatal("expected presence failure for MOCK_LOCK_STATE=locked")
	}
	if !errors.Is(err, ErrPresenceFailed) {
		t.Fatalf("expected ErrPresenceFailed, got: %v", err)
	}

	// 2. Sleeping mock state
	t.Setenv("MOCK_LOCK_STATE", "sleeping")
	err = checker.CheckPresence(context.Background())
	if err == nil || !errors.Is(err, ErrPresenceFailed) {
		t.Fatalf("expected ErrPresenceFailed for sleeping state, got: %v", err)
	}

	// 3. Lid closed mock state
	t.Setenv("MOCK_LOCK_STATE", "lid_closed")
	err = checker.CheckPresence(context.Background())
	if err == nil || !errors.Is(err, ErrPresenceFailed) {
		t.Fatalf("expected ErrPresenceFailed for lid_closed state, got: %v", err)
	}

	// 4. Unlocked / active mock state
	t.Setenv("MOCK_LOCK_STATE", "unlocked")
	err = checker.CheckPresence(context.Background())
	if err != nil {
		t.Fatalf("expected presence success for MOCK_LOCK_STATE=unlocked, got: %v", err)
	}

	// 5. Present mock state
	t.Setenv("MOCK_LOCK_STATE", "present")
	err = checker.CheckPresence(context.Background())
	if err != nil {
		t.Fatalf("expected presence success for MOCK_LOCK_STATE=present, got: %v", err)
	}
}

func TestPresence_AuditLogRecording(t *testing.T) {
	tmpDir := t.TempDir()
	auditLogPath := filepath.Join(tmpDir, "audit.log")

	testErr := errors.New("workstation screen locked")
	LogPresenceRejection(auditLogPath, "slack_get_channel_history", "sess_test_123", testErr)

	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Fatalf("failed reading audit log: %v", err)
	}

	var entry AuditLogEntry
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("failed unmarshaling audit log entry: %v", err)
	}

	if entry.Event != "ZERO_BACKGROUND_AUTHORITY_BLOCKED" {
		t.Errorf("expected event ZERO_BACKGROUND_AUTHORITY_BLOCKED, got %s", entry.Event)
	}
	if entry.Tool != "slack_get_channel_history" {
		t.Errorf("expected tool slack_get_channel_history, got %s", entry.Tool)
	}
	if entry.SessionID != "sess_test_123" {
		t.Errorf("expected session sess_test_123, got %s", entry.SessionID)
	}
	if entry.Error != "Zero-Background-Authority: User presence failed / locked" {
		t.Errorf("expected standard error string, got %s", entry.Error)
	}
	if !strings.Contains(entry.Reason, "workstation screen locked") {
		t.Errorf("expected reason to contain 'workstation screen locked', got %s", entry.Reason)
	}
}

func TestShim_HardwarePresenceGating(t *testing.T) {
	tmpDir := t.TempDir()
	auditLogPath := filepath.Join(tmpDir, "conjoiner_audit.log")

	cfg := Config{
		TargetCommand:           "/bin/cat",
		AllowedScopes:           []string{"tool:exec:slack_get_channel_history"},
		RequireHardwarePresence: true,
		AuditLogPath:            auditLogPath,
	}

	shim, err := NewTransportShim(cfg)
	if err != nil {
		t.Fatalf("failed initializing shim: %v", err)
	}

	// 1. When locked: tools/call must fail closed with -32001
	t.Setenv("MOCK_LOCK_STATE", "locked")

	var serverIn bytes.Buffer
	var clientOut bytes.Buffer
	callMsg := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"slack_get_channel_history","arguments":{}}}`

	forwarded := shim.handleInboundLine([]byte(callMsg), &serverIn, &clientOut)
	if forwarded {
		t.Fatal("expected tools/call to be blocked when presence check fails")
	}

	var resp JSONRPCMessage
	if err := json.Unmarshal(clientOut.Bytes(), &resp); err != nil {
		t.Fatalf("failed unmarshaling error response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error, got nil")
	}
	if resp.Error.Code != -32001 {
		t.Fatalf("expected error code -32001, got %d", resp.Error.Code)
	}
	if resp.Error.Message != "Zero-Background-Authority: User presence failed / locked" {
		t.Fatalf("expected exact error message 'Zero-Background-Authority: User presence failed / locked', got %q", resp.Error.Message)
	}

	// Verify forensic entry in audit log
	auditData, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Fatalf("failed reading audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "ZERO_BACKGROUND_AUTHORITY_BLOCKED") {
		t.Fatalf("expected audit log to record rejection, got: %s", string(auditData))
	}

	// 2. When unlocked: tools/call passes presence gate
	t.Setenv("MOCK_LOCK_STATE", "unlocked")
	serverIn.Reset()
	clientOut.Reset()

	forwarded = shim.handleInboundLine([]byte(callMsg), &serverIn, &clientOut)
	if !forwarded {
		t.Fatalf("expected tools/call to be forwarded when user presence is active: %s", clientOut.String())
	}
}
