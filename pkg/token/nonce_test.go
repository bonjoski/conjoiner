package token

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSessionBoundNonce_GenerationAndBinding(t *testing.T) {
	sessionID := "session-agent-alpha-42"
	nonce, err := GenerateSessionNonce(sessionID)
	if err != nil {
		t.Fatalf("unexpected nonce generation error: %v", err)
	}

	if !strings.HasPrefix(nonce, sessionID+".") {
		t.Fatalf("nonce %q does not begin with sessionID prefix", nonce)
	}

	now := time.Now().UTC()
	if err := VerifySessionNonceBinding(nonce, sessionID, 60*time.Second, now); err != nil {
		t.Fatalf("expected valid session nonce binding, got: %v", err)
	}

	// Mismatched session must be rejected
	err = VerifySessionNonceBinding(nonce, "session-attacker-evil", 60*time.Second, now)
	if !errors.Is(err, ErrSessionNonceMismatch) {
		t.Fatalf("expected ErrSessionNonceMismatch, got: %v", err)
	}

	// Expired nonce must be rejected
	future := now.Add(5 * time.Minute)
	err = VerifySessionNonceBinding(nonce, sessionID, 60*time.Second, future)
	if !errors.Is(err, ErrSessionNonceExpired) {
		t.Fatalf("expected ErrSessionNonceExpired, got: %v", err)
	}
}

func TestSessionNonceTracker_ReplayProtection(t *testing.T) {
	sessionID := "session-agent-replay"
	tracker := NewSessionNonceTracker(NewMemoryReplayCache(), 60*time.Second)

	nonce, err := GenerateSessionNonce(sessionID)
	if err != nil {
		t.Fatal(err)
	}

	// First use: must succeed
	if err := tracker.ValidateAndConsume(sessionID, nonce); err != nil {
		t.Fatalf("first use failed: %v", err)
	}

	// Replay attempt: must fail closed
	err = tracker.ValidateAndConsume(sessionID, nonce)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected on nonce reuse, got: %v", err)
	}
}

func TestDPoPProof_WithNonceVerification(t *testing.T) {
	dpopKey, err := GenerateDPoPKey()
	if err != nil {
		t.Fatal(err)
	}

	sessionID := "sess-dpop-test"
	nonce, err := GenerateSessionNonce(sessionID)
	if err != nil {
		t.Fatal(err)
	}

	htm := "EXEC"
	htu := "tool://test_tool"
	accessToken := "sample-jwt-token"

	// 1. Proof created with nonce
	proof, err := dpopKey.CreateProofWithNonce(htm, htu, accessToken, nonce)
	if err != nil {
		t.Fatalf("CreateProofWithNonce failed: %v", err)
	}

	now := time.Now().UTC()
	cache := NewMemoryReplayCache()

	// Validation with matching nonce succeeds
	payload, _, err := ValidateProofWithNonce(proof, htm, htu, accessToken, nonce, 30*time.Second, cache, now)
	if err != nil {
		t.Fatalf("expected validation with correct nonce to succeed, got: %v", err)
	}
	if payload.Nonce != nonce {
		t.Fatalf("expected payload.Nonce=%q, got %q", nonce, payload.Nonce)
	}

	// Validation with wrong expected nonce fails
	cache2 := NewMemoryReplayCache()
	_, _, err = ValidateProofWithNonce(proof, htm, htu, accessToken, "wrong-nonce", 30*time.Second, cache2, now)
	if !errors.Is(err, ErrDPoPNonceMismatch) {
		t.Fatalf("expected ErrDPoPNonceMismatch, got: %v", err)
	}

	// Proof without nonce validated against expected nonce fails
	proofWithoutNonce, _ := dpopKey.CreateProof(htm, htu, accessToken)
	_, _, err = ValidateProofWithNonce(proofWithoutNonce, htm, htu, accessToken, nonce, 30*time.Second, cache2, now)
	if !errors.Is(err, ErrDPoPNonceRequired) {
		t.Fatalf("expected ErrDPoPNonceRequired, got: %v", err)
	}
}
