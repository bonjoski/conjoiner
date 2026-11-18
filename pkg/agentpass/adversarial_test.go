package agentpass

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// TestAdversarial_N8MultiAgentConcurrency simulates 8 parallel autonomous subagents
// deriving child passes and executing tool calls simultaneously.
func TestAdversarial_N8MultiAgentConcurrency(t *testing.T) {
	_, priv := generateTestKeys(t)
	now := time.Now()

	rootOpts := IssueOptions{
		AgentID:         "agent:lead",
		HumanSupervisor: "benskolmoski@bonjo.dev",
		Scope:           []string{"repo:read", "repo:write", "git:status", "git:commit", "git:push"},
		Lifetime:        2 * time.Hour,
		MaxDepth:        3,
	}

	rootPass, _, err := IssueRootPass(rootOpts, priv, now)
	if err != nil {
		t.Fatalf("failed issuing root pass: %v", err)
	}

	os.Setenv("CONJOINER_MOCK_BIOMETRIC", "approved")
	defer os.Unsetenv("CONJOINER_MOCK_BIOMETRIC")

	gate := NewHardwareGate()
	gate.SetLeaseTTL(5 * time.Minute)

	const numSubagents = 8
	var wg sync.WaitGroup
	errCh := make(chan error, numSubagents*2)

	for i := 0; i < numSubagents; i++ {
		wg.Add(1)
		subID := fmt.Sprintf("subagent-%02d", i)

		go func(id string) {
			defer wg.Done()

			// 1. Derive attenuated child pass
			childOpts := AttenuateOptions{
				RequestedScope: []string{"repo:read", "git:commit"},
				ChildAgentID:   id,
				ChildDPoPThumb: fmt.Sprintf("jkt_%s", id),
				Lifetime:       30 * time.Minute,
			}

			childPass, _, err := AttenuatePass(rootPass, childOpts, priv, now)
			if err != nil {
				errCh <- fmt.Errorf("[%s] attenuation failed: %w", id, err)
				return
			}

			// 2. Hardware check & authorize
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if err := gate.CheckAndAuthorize(ctx, childPass, "git:commit"); err != nil {
				errCh <- fmt.Errorf("[%s] hardware authorization failed: %w", id, err)
				return
			}

			// 3. Mint short-lived tool token
			_, _, err = MintToolToken(childPass, "git:commit", priv, now)
			if err != nil {
				errCh <- fmt.Errorf("[%s] token minting failed: %w", id, err)
				return
			}
		}(subID)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrency failure: %v", err)
	}
}

// TestAdversarial_ScopeSmugglingAndNULInjection tests injection of malicious characters
// (NUL bytes, path traversals) into AgentPass requested scopes.
func TestAdversarial_ScopeSmugglingAndNULInjection(t *testing.T) {
	_, priv := generateTestKeys(t)
	now := time.Now()

	rootOpts := IssueOptions{
		AgentID:         "agent:root",
		HumanSupervisor: "lead@bonjo.dev",
		Scope:           []string{"fs:read:/workspace", "repo:read"},
	}

	rootPass, _, err := IssueRootPass(rootOpts, priv, now)
	if err != nil {
		t.Fatalf("failed root setup: %v", err)
	}

	maliciousVectors := []string{
		"fs:read:/workspace/../etc/shadow",
		"fs:read:/workspace\x00/admin",
		"repo:read:*\x00",
		"*",
		"admin:iam:delete",
	}

	for _, vector := range maliciousVectors {
		t.Run("vector_"+vector, func(t *testing.T) {
			childOpts := AttenuateOptions{
				RequestedScope: []string{vector},
			}
			_, _, err := AttenuatePass(rootPass, childOpts, priv, now)
			if err == nil {
				t.Fatalf("expected rejection for malicious vector '%s', but was allowed", vector)
			}
		})
	}
}

// TestAdversarial_TOCTOUExpiredParent tests that attenuating from or minting against
// an expired parent pass immediately fails closed.
func TestAdversarial_TOCTOUExpiredParent(t *testing.T) {
	_, priv := generateTestKeys(t)
	now := time.Now()

	rootOpts := IssueOptions{
		AgentID:         "agent:root",
		HumanSupervisor: "lead@bonjo.dev",
		Scope:           []string{"repo:read", "git:status"},
		Lifetime:        10 * time.Second,
	}

	rootPass, _, err := IssueRootPass(rootOpts, priv, now)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	futureTime := now.Add(15 * time.Second)

	// Attempt attenuation after expiry
	_, _, err = AttenuatePass(rootPass, AttenuateOptions{
		RequestedScope: []string{"repo:read"},
	}, priv, futureTime)
	if err != ErrExpiredPass {
		t.Errorf("expected ErrExpiredPass on attenuation, got: %v", err)
	}

	// Attempt tool token minting after expiry
	_, _, err = MintToolToken(rootPass, "git:status", priv, futureTime)
	if err != ErrExpiredPass {
		t.Errorf("expected ErrExpiredPass on mint, got: %v", err)
	}
}

// TestAdversarial_BiometricBypassRejected verifies that an attacker cannot bypass
// hardware gates for critical risk actions when biometric validation is denied.
func TestAdversarial_BiometricBypassRejected(t *testing.T) {
	os.Setenv("CONJOINER_MOCK_BIOMETRIC", "denied")
	defer os.Unsetenv("CONJOINER_MOCK_BIOMETRIC")

	gate := NewHardwareGate()

	pass := &AgentPass{
		AgentID:         "agent:attacker",
		SessionID:       "sess-attack",
		HumanSupervisor: "supervisor@bonjo.dev",
		RequireHardware: true,
	}

	ctx := context.Background()

	// High risk action: git:push
	err := gate.CheckAndAuthorize(ctx, pass, "git:push")
	if err == nil {
		t.Fatalf("expected biometric rejection, got nil")
	}

	// Critical risk action: iam:delete
	err = gate.CheckAndAuthorize(ctx, pass, "iam:delete")
	if err == nil {
		t.Fatalf("expected critical biometric rejection, got nil")
	}
}
