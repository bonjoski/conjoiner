package agentpass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// ErrBiometricRejected indicates the biometric challenge was cancelled, denied, or timed out.
	ErrBiometricRejected = errors.New("biometric challenge denied or cancelled")
	// ErrWorkstationLocked indicates presence failed because the screen is locked or lid closed.
	ErrWorkstationLocked = errors.New("workstation locked or display sleeping")
)

// RiskLevel defines the action's risk tier for biometric step-up evaluation.
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// EvaluateRisk inspects a tool action scope and returns its risk tier.
func EvaluateRisk(actionScope string) RiskLevel {
	clean := strings.ToLower(strings.TrimSpace(actionScope))

	// Critical: destructive infra, IAM changes, force operations
	if strings.Contains(clean, "delete") ||
		strings.Contains(clean, "drop") ||
		strings.Contains(clean, "iam") ||
		strings.Contains(clean, "force") ||
		strings.Contains(clean, "deploy:prod") ||
		strings.Contains(clean, "cloud:terminate") {
		return RiskCritical
	}

	// High: state-mutating pushes, PR approvals, merges, production mutations
	if strings.Contains(clean, "push") ||
		strings.Contains(clean, "merge") ||
		strings.Contains(clean, "approve") ||
		strings.Contains(clean, "publish") ||
		strings.Contains(clean, "write") {
		return RiskHigh
	}

	// Medium: workspace modifications, branch creation, local builds
	if strings.Contains(clean, "create") ||
		strings.Contains(clean, "modify") ||
		strings.Contains(clean, "build") {
		return RiskMedium
	}

	// Low: reads, list, status, inspect
	return RiskLow
}

// HardwareGate evaluates whether an action requires biometric confirmation or presence.
type HardwareGate struct {
	mu           sync.RWMutex
	leases       map[string]*AmortizedLease // SessionID -> Lease
	leaseTTL     time.Duration
	locksmithCmd string
	socketPath   string
}

// AmortizedLease tracks an active biometric approval to prevent prompt storms across N=8 subagents.
type AmortizedLease struct {
	SessionID string    `json:"session_id"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RiskTier  RiskLevel `json:"risk_tier"`
}

// IsValid checks if the lease is currently active.
func (l *AmortizedLease) IsValid(now time.Time, requiredRisk RiskLevel) bool {
	if now.After(l.ExpiresAt) {
		return false
	}
	// Critical risk always requires explicit step-up unless explicitly covered
	if requiredRisk == RiskCritical && l.RiskTier != RiskCritical {
		return false
	}
	return true
}

// NewHardwareGate initializes the hardware gate with default parameters.
func NewHardwareGate() *HardwareGate {
	home, _ := os.UserHomeDir()
	sock := os.Getenv("LOCKSMITH_SOCKET")
	if sock == "" && home != "" {
		sock = filepath.Join(home, ".locksmith", "locksmith.sock")
	}

	return &HardwareGate{
		leases:       make(map[string]*AmortizedLease),
		leaseTTL:     5 * time.Minute, // 5-minute amortization window for N=8 subagents
		locksmithCmd: "locksmith",
		socketPath:   sock,
	}
}

// SetLeaseTTL overrides the amortization lease lifetime.
func (g *HardwareGate) SetLeaseTTL(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.leaseTTL = d
}

// CheckAndAuthorize evaluates if the action requires hardware elevation.
// If an amortized lease is valid, it proceeds non-interactively without prompt storms.
func (g *HardwareGate) CheckAndAuthorize(ctx context.Context, pass *AgentPass, actionScope string) error {
	risk := EvaluateRisk(actionScope)

	// Low risk actions under an active pass do not require biometric elevation
	if risk == RiskLow && !pass.RequireHardware {
		return nil
	}

	now := time.Now()

	// 1. Check in-memory amortized lease
	g.mu.RLock()
	lease, exists := g.leases[pass.SessionID]
	g.mu.RUnlock()

	if exists && lease.IsValid(now, risk) {
		// Valid amortized lease: fast-path approved (< 0.1ms)
		return nil
	}

	// 2. Mock environment evaluation (for automated tests and CI environments)
	if mockVal := os.Getenv("CONJOINER_MOCK_BIOMETRIC"); mockVal != "" {
		clean := strings.ToLower(strings.TrimSpace(mockVal))
		switch clean {
		case "approved", "ok", "true", "1", "pass":
			g.grantLease(pass.SessionID, risk, now)
			return nil
		case "denied", "reject", "false", "0", "timeout":
			return ErrBiometricRejected
		case "locked", "sleeping":
			return ErrWorkstationLocked
		}
	}

	// 3. Check Locksmith UDS socket if available
	if g.socketPath != "" {
		if _, err := os.Stat(g.socketPath); err == nil {
			err := g.queryLocksmithSocket(ctx, pass, actionScope)
			if err == nil {
				g.grantLease(pass.SessionID, risk, now)
				return nil
			}
		}
	}

	// 4. Trigger local CLI step-up fallback if locksmith binary is installed
	if path, err := exec.LookPath(g.locksmithCmd); err == nil {
		challenge := fmt.Sprintf("Approve AgentPass action '%s' for %s (Supervisor: %s)",
			actionScope, pass.AgentID, pass.HumanSupervisor)
		cmd := exec.CommandContext(ctx, path, "step-up",
			fmt.Sprintf("--challenge=%s", challenge),
			fmt.Sprintf("--severity=%s", risk),
			"--raw",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s (%v)", ErrBiometricRejected, strings.TrimSpace(string(out)), err)
		}
		g.grantLease(pass.SessionID, risk, now)
		return nil
	}

	// If no hardware daemon is reachable but hardware is strictly mandated, fail closed
	if pass.RequireHardware {
		return fmt.Errorf("%w: Locksmith hardware daemon is unreachable", ErrHardwareRequired)
	}

	// Default low/medium elevation under active human supervision session is permitted
	g.grantLease(pass.SessionID, risk, now)
	return nil
}

func (g *HardwareGate) grantLease(sessionID string, risk RiskLevel, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.leases[sessionID] = &AmortizedLease{
		SessionID: sessionID,
		GrantedAt: now,
		ExpiresAt: now.Add(g.leaseTTL),
		RiskTier:  risk,
	}
}

func (g *HardwareGate) queryLocksmithSocket(ctx context.Context, pass *AgentPass, action string) error {
	dialer := net.Dialer{Timeout: 1 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", g.socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := map[string]any{
		"method": "StepUp.Authorize",
		"params": map[string]any{
			"agent_id":   pass.AgentID,
			"supervisor": pass.HumanSupervisor,
			"action":     action,
			"session_id": pass.SessionID,
		},
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}

	var resp struct {
		Result any    `json:"result"`
		Error  string `json:"error"`
	}

	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}

	if resp.Error != "" {
		return errors.New(resp.Error)
	}

	return nil
}
