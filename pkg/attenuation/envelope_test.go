package attenuation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestDelegationEnvelope(t *testing.T) {
	parentPub, parentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating parent keypair: %v", err)
	}

	childPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating child keypair: %v", err)
	}

	parentScopes, err := NewScopeSet("fs:read:/tmp/workspace", "tool:exec:git:*")
	if err != nil {
		t.Fatalf("failed creating parent scopes: %v", err)
	}

	childScopes, err := NewScopeSet("fs:read:/tmp/workspace/src", "tool:exec:git:status")
	if err != nil {
		t.Fatalf("failed creating child scopes: %v", err)
	}

	env, err := CreateEnvelope(
		"token-root-01",
		childPub,
		parentPriv,
		parentScopes,
		childScopes,
		30*time.Second,
		1,
	)
	if err != nil {
		t.Fatalf("failed creating delegation envelope: %v", err)
	}

	// Verify valid envelope
	now := time.Now().UTC()
	if err := env.Verify(parentPub, now); err != nil {
		t.Fatalf("expected envelope verification to succeed, got: %v", err)
	}

	// Verify with wrong public key fails
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := env.Verify(wrongPub, now); err == nil {
		t.Fatalf("expected error verifying with wrong public key, got nil")
	}

	// Verify expired envelope fails
	future := now.Add(35 * time.Second)
	if err := env.Verify(parentPub, future); err == nil {
		t.Fatalf("expected error verifying expired envelope, got nil")
	}
}

func TestDelegationChainMonotonicDecay(t *testing.T) {
	// Root -> Agent1 -> Agent2
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	agent1Pub, agent1Priv, _ := ed25519.GenerateKey(rand.Reader)
	agent2Pub, _, _ := ed25519.GenerateKey(rand.Reader)

	rootScopes, _ := NewScopeSet("fs:read:/tmp/workspace", "tool:exec:git:*")
	agent1Scopes, _ := NewScopeSet("fs:read:/tmp/workspace/pkg", "tool:exec:git:*")
	agent2Scopes, _ := NewScopeSet("fs:read:/tmp/workspace/pkg/token", "tool:exec:git:status")

	env1, err := CreateEnvelope("root", agent1Pub, rootPriv, rootScopes, agent1Scopes, 30*time.Second, 1)
	if err != nil {
		t.Fatalf("failed creating env1: %v", err)
	}

	env2, err := CreateEnvelope("token-agent1", agent2Pub, agent1Priv, agent1Scopes, agent2Scopes, 30*time.Second, 2)
	if err != nil {
		t.Fatalf("failed creating env2: %v", err)
	}

	chain := []DelegationEnvelope{*env1, *env2}
	now := time.Now().UTC()
	if err := VerifyChain(chain, rootPub, now); err != nil {
		t.Fatalf("expected chain verification to succeed, got: %v", err)
	}

	// If agent2 requests permission not in agent1 (e.g. fs:read:/tmp/workspace/other)
	invalidAgent2Scopes, _ := NewScopeSet("fs:read:/tmp/workspace/other")
	_, err = CreateEnvelope("token-agent1", agent2Pub, agent1Priv, agent1Scopes, invalidAgent2Scopes, 30*time.Second, 2)
	if err == nil {
		t.Fatalf("expected error creating envelope with escalated scope, got nil")
	}
}
