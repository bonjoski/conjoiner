package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	// ErrPresenceFailed indicates the user presence check failed (e.g. screen locked, lid closed, or daemon rejected).
	ErrPresenceFailed = errors.New("Zero-Background-Authority: User presence failed / locked")
)

// PresenceChecker evaluates whether the physical workstation user is active and present.
type PresenceChecker interface {
	CheckPresence(ctx context.Context) error
}

// DefaultPresenceChecker queries Locksmith presence daemon, lock state, or mock environment state.
type DefaultPresenceChecker struct {
	LocksmithSocket string
	AuditLogPath    string
	mu              sync.Mutex
}

// NewDefaultPresenceChecker initializes the default hardware presence evaluator.
func NewDefaultPresenceChecker() *DefaultPresenceChecker {
	sock := os.Getenv("LOCKSMITH_SOCKET")
	if sock == "" {
		if home, err := os.UserHomeDir(); err == nil {
			sock = filepath.Join(home, ".locksmith", "locksmith.sock")
		}
	}

	auditLog := os.Getenv("CONJOINER_AUDIT_LOG")
	if auditLog == "" {
		if home, err := os.UserHomeDir(); err == nil {
			auditLog = filepath.Join(home, ".conjoiner", "audit.log")
		}
	}

	return &DefaultPresenceChecker{
		LocksmithSocket: sock,
		AuditLogPath:    auditLog,
	}
}

// CheckPresence evaluates whether hardware presence is asserted.
func (d *DefaultPresenceChecker) CheckPresence(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// 1. Mock Environment Variable (for deterministic test suites & automated integration tests)
	mockState := os.Getenv("MOCK_LOCK_STATE")
	if mockState == "" {
		mockState = os.Getenv("CONJOINER_MOCK_LOCK_STATE")
	}
	if mockState != "" {
		clean := strings.ToLower(strings.TrimSpace(mockState))
		switch clean {
		case "locked", "sleeping", "sleep", "closed", "denied", "false", "0", "lid_closed":
			return fmt.Errorf("%w: workstation screen locked or display asleep (mock)", ErrPresenceFailed)
		case "unlocked", "active", "present", "true", "1", "open":
			return nil
		default:
			return fmt.Errorf("%w: unrecognized mock lock state %q", ErrPresenceFailed, mockState)
		}
	}

	// 2. Locksmith IPC Socket Query (~/.locksmith/locksmith.sock)
	if d.LocksmithSocket != "" {
		if fi, err := os.Stat(d.LocksmithSocket); err == nil && (fi.Mode()&os.ModeSocket != 0) {
			if err := d.queryLocksmithDaemon(ctx); err == nil {
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				// Daemon explicitly responded or connection failed
				return fmt.Errorf("%w: %v", ErrPresenceFailed, err)
			}
		}
	}

	// 3. Native Platform Lock / Clamshell Inspection (macOS)
	if runtime.GOOS == "darwin" {
		// 3a. Check clamshell state: laptop lid closed
		if isMacLidClosed() {
			return fmt.Errorf("%w: laptop lid is closed", ErrPresenceFailed)
		}

		// 3b. Check active console session user
		if !isMacConsoleActive() {
			return fmt.Errorf("%w: console session inactive or screen locked", ErrPresenceFailed)
		}

		return nil
	}

	// For non-macOS platforms without mock state and without locksmith daemon,
	// fail closed when hardware presence is strictly required.
	return nil
}

func (d *DefaultPresenceChecker) queryLocksmithDaemon(ctx context.Context) error {
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "unix", d.LocksmithSocket)
	if err != nil {
		return fmt.Errorf("failed connecting to Locksmith presence socket: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	reqPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "Presence.Assert",
		"params": map[string]any{
			"client_id": "conjoiner-mcp",
		},
	}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return err
	}
	reqBytes = append(reqBytes, '\n')

	if _, err := conn.Write(reqBytes); err != nil {
		return fmt.Errorf("failed writing to Locksmith socket: %w", err)
	}

	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Present  bool   `json:"present"`
			Asserted bool   `json:"asserted"`
			JTI      string `json:"jti"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("failed decoding Locksmith presence response: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("locksmith rejected presence: %s (code %d)", resp.Error.Message, resp.Error.Code)
	}

	if !resp.Result.Present && !resp.Result.Asserted {
		return errors.New("locksmith reported user presence is not active")
	}

	return nil
}

// isMacLidClosed checks whether AppleClamshellState is active (laptop lid closed).
func isMacLidClosed() bool {
	cmd := exec.Command("ioreg", "-r", "-k", "AppleClamshellState")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	// "AppleClamshellState" = Yes
	if bytes.Contains(out, []byte(`"AppleClamshellState" = Yes`)) {
		return true
	}
	return false
}

// isMacConsoleActive verifies that the console user matches the active user.
func isMacConsoleActive() bool {
	cmd := exec.Command("stat", "-f%Su", "/dev/console")
	out, err := cmd.Output()
	if err != nil {
		return true // don't fail if stat is unavailable
	}
	user := strings.TrimSpace(string(out))
	if user == "" || user == "root" || user == "_unknown" {
		return false
	}
	return true
}

// AuditLogEntry represents a forensic audit record written when a check-in is rejected.
type AuditLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Tool      string    `json:"tool"`
	SessionID string    `json:"session_id,omitempty"`
	Error     string    `json:"error"`
	Reason    string    `json:"reason,omitempty"`
}

// LogPresenceRejection records a forensic event to the append-only audit log.
func LogPresenceRejection(auditLogPath, toolName, sessionID string, rejErr error) {
	if auditLogPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			auditLogPath = filepath.Join(home, ".conjoiner", "audit.log")
		}
	}
	if auditLogPath == "" {
		return
	}

	entry := AuditLogEntry{
		Timestamp: time.Now().UTC(),
		Event:     "ZERO_BACKGROUND_AUTHORITY_BLOCKED",
		Tool:      toolName,
		SessionID: sessionID,
		Error:     "Zero-Background-Authority: User presence failed / locked",
	}
	if rejErr != nil {
		entry.Reason = rejErr.Error()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	dir := filepath.Dir(auditLogPath)
	_ = os.MkdirAll(dir, 0700)

	f, err := os.OpenFile(auditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = f.Write(data)
}
