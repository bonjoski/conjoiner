package token

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// TestDPoPProofValidation satisfies deliverable: test_dpop_proof_validation
func TestDPoPProofValidation(t *testing.T) {
	t.Run("test_dpop_proof_validation", func(t *testing.T) {
		key, err := GenerateDPoPKey()
		if err != nil {
			t.Fatalf("failed to generate dpop key: %v", err)
		}

		now := time.Now().UTC()
		replayCache := NewMemoryReplayCache()

		htm := "POST"
		htu := "https://iam.broker.local/token"
		accessToken := "test-access-token-xyz"

		// 1. Success case
		proof, err := key.CreateProof(htm, htu, accessToken)
		if err != nil {
			t.Fatalf("failed to create proof: %v", err)
		}

		payload, jwk, err := ValidateProof(proof, htm, htu, accessToken, 30*time.Second, replayCache, now)
		if err != nil {
			t.Fatalf("expected proof validation to succeed, got: %v", err)
		}

		if payload.HTM != htm {
			t.Errorf("expected htm %s, got %s", htm, payload.HTM)
		}
		if payload.HTU != htu {
			t.Errorf("expected htu %s, got %s", htu, payload.HTU)
		}
		if jwk.Thumbprint() != key.Thumbprint() {
			t.Errorf("expected thumbprint %s, got %s", key.Thumbprint(), jwk.Thumbprint())
		}

		// 2. Replay detection (re-submitting identical proof with same JTI)
		_, _, err = ValidateProof(proof, htm, htu, accessToken, 30*time.Second, replayCache, now)
		if err == nil {
			t.Fatalf("expected replayed proof to fail, got nil")
		}
		if !errors.Is(err, ErrDPoPProofReplayed) {
			t.Errorf("expected ErrDPoPProofReplayed, got: %v", err)
		}

		// 3. Method mismatch
		newProof, _ := key.CreateProof("POST", htu, accessToken)
		_, _, err = ValidateProof(newProof, "GET", htu, accessToken, 30*time.Second, replayCache, now)
		if err == nil || !errors.Is(err, ErrMethodMismatch) {
			t.Errorf("expected ErrMethodMismatch, got: %v", err)
		}

		// 4. URI mismatch
		newProof2, _ := key.CreateProof(htm, "https://wrong.uri", accessToken)
		_, _, err = ValidateProof(newProof2, htm, htu, accessToken, 30*time.Second, replayCache, now)
		if err == nil || !errors.Is(err, ErrURIMismatch) {
			t.Errorf("expected ErrURIMismatch, got: %v", err)
		}

		// 5. Access token hash (ath) mismatch
		newProof3, _ := key.CreateProof(htm, htu, "token-A")
		_, _, err = ValidateProof(newProof3, htm, htu, "token-B", 30*time.Second, replayCache, now)
		if err == nil || !errors.Is(err, ErrATHMismatch) {
			t.Errorf("expected ErrATHMismatch, got: %v", err)
		}

		// 6. Clock skew / Expiration
		future := now.Add(45 * time.Second)
		newProof4, _ := key.CreateProof(htm, htu, accessToken)
		_, _, err = ValidateProof(newProof4, htm, htu, accessToken, 30*time.Second, replayCache, future)
		if err == nil || !errors.Is(err, ErrDPoPProofExpired) {
			t.Errorf("expected ErrDPoPProofExpired, got: %v", err)
		}
	})
}

func TestDPoPKeyZeroization(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	if len(key.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(key.PrivateKey))
	}

	key.Zeroize()

	if key.PrivateKey != nil {
		t.Errorf("expected private key to be nil after zeroization")
	}

	_, err = key.CreateProof("POST", "https://test", "")
	if err == nil {
		t.Errorf("expected error creating proof with zeroized key, got nil")
	}
}

func TestMalformedDPoPProofs(t *testing.T) {
	now := time.Now().UTC()
	cache := NewMemoryReplayCache()

	cases := []string{
		"not-enough-parts",
		"part1.part2",
		"invalid-base64.part2.part3",
		"..",
	}

	for _, tc := range cases {
		_, _, err := ValidateProof(tc, "POST", "https://uri", "", 30*time.Second, cache, now)
		if err == nil {
			t.Errorf("expected error for malformed proof '%s', got nil", tc)
		}
	}
}

func TestReplayCachePurge(t *testing.T) {
	cache := NewMemoryReplayCache()
	now := time.Now().UTC()

	_ = cache.CheckAndSet("id-1", now.Add(-10*time.Second)) // Expired
	_ = cache.CheckAndSet("id-2", now.Add(10*time.Second))  // Valid

	cache.PurgeExpired(now)

	if cache.Len() != 1 {
		t.Errorf("expected 1 entry after purge, got %d", cache.Len())
	}
}

func TestDeriveDPoPSubkey(t *testing.T) {
	rootKey := []byte("super-secret-root-key-32-bytes!!")
	sessionID := "ses-workstation-alpha-42"
	epoch := int64(1)

	// 1. Derivation must be deterministic across restarts
	key1, err := DeriveDPoPSubkey(rootKey, sessionID, epoch)
	if err != nil {
		t.Fatalf("Failed to derive DPoP key 1: %v", err)
	}

	key2, err := DeriveDPoPSubkey(rootKey, sessionID, epoch)
	if err != nil {
		t.Fatalf("Failed to derive DPoP key 2: %v", err)
	}

	if key1.Thumbprint() != key2.Thumbprint() {
		t.Fatalf("Expected identical thumbprint from deterministic derivation, got %s vs %s", key1.Thumbprint(), key2.Thumbprint())
	}

	// 2. Different epoch must produce distinct subkey
	keyEpoch2, err := DeriveDPoPSubkey(rootKey, sessionID, 2)
	if err != nil {
		t.Fatalf("Failed to derive epoch 2 key: %v", err)
	}
	if key1.Thumbprint() == keyEpoch2.Thumbprint() {
		t.Fatal("Expected different epoch to produce different thumbprint")
	}

	// 3. Different sessionID must produce distinct subkey
	keyOtherSession, err := DeriveDPoPSubkey(rootKey, "ses-other", 1)
	if err != nil {
		t.Fatalf("Failed to derive other session key: %v", err)
	}
	if key1.Thumbprint() == keyOtherSession.Thumbprint() {
		t.Fatal("Expected different session to produce different thumbprint")
	}

	// 4. Short key must fail closed
	_, err = DeriveDPoPSubkey([]byte("short"), sessionID, 1)
	if err == nil {
		t.Fatal("Expected short key < 16 bytes to fail")
	}
}
