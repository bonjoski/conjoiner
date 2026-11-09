package token

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestCNJ02_StolenSubjectTokenRequiresParentDPoPPoP verifies that a stolen `SubjectToken` JWT
// cannot be exchanged by an attacker lacking the parent DPoP private key.
func TestCNJ02_StolenSubjectTokenRequiresParentDPoPPoP(t *testing.T) {
	const pinnedURI = "https://broker.bonjoski.local/oauth2/token"
	broker, err := NewTokenBroker(BrokerConfig{
		ExchangeURI: pinnedURI,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	victimParentKey, _ := GenerateDPoPKey()
	attackerChildKey, _ := GenerateDPoPKey()
	attackerFakeParentKey, _ := GenerateDPoPKey()

	_, stolenRootJWT, err := broker.IssueRootToken(ctx, RootTokenRequest{
		Subject:        "victim-agent",
		Scopes:         []string{"fs:read:/tmp/workspace", "tool:exec:git:*"},
		TTL:            30 * time.Second,
		DPoPThumbprint: victimParentKey.Thumbprint(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Attacker omits ParentDPoPProof and presents attackerChildKey -> MUST fail with ErrDPoPBindingMismatch
	attackerChildProof, _ := attackerChildKey.CreateProof("POST", pinnedURI, "")
	_, _, err = broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     stolenRootJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"tool:exec:git:status"},
		DPoPProof:        attackerChildProof,
		ExchangeURI:      pinnedURI,
	})
	if !errors.Is(err, ErrDPoPBindingMismatch) {
		t.Fatalf("CNJ-02 FAILED: stolen SubjectToken exchanged without ParentDPoPProof (err=%v)", err)
	}

	// 2. Attacker signs ParentDPoPProof with wrong key -> MUST fail with ErrDPoPBindingMismatch
	attackerChildProof2, _ := attackerChildKey.CreateProof("POST", pinnedURI, "")
	fakeParentProof, _ := attackerFakeParentKey.CreateProof("POST", pinnedURI, stolenRootJWT)
	_, _, err = broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     stolenRootJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"tool:exec:git:status"},
		DPoPProof:        attackerChildProof2,
		ParentDPoPProof:  fakeParentProof,
		ExchangeURI:      pinnedURI,
	})
	if !errors.Is(err, ErrDPoPBindingMismatch) {
		t.Fatalf("CNJ-02 FAILED: rogue ParentDPoPProof accepted (err=%v)", err)
	}

	// 3. Wrong HTU on DPoP proof when BrokerConfig.ExchangeURI is pinned -> MUST fail with ErrURIMismatch
	wrongURIProof, _ := victimParentKey.CreateProof("POST", "https://evil.example/token", stolenRootJWT)
	_, _, err = broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     stolenRootJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"tool:exec:git:status"},
		DPoPProof:        wrongURIProof,
	})
	if !errors.Is(err, ErrURIMismatch) {
		t.Fatalf("CNJ-02 FAILED: mismatched HTU accepted against pinned broker URI (err=%v)", err)
	}

	// 4. Legitimate delegation with valid victimParentKey ParentDPoPProof + child key succeeds
	legitChildKey, _ := GenerateDPoPKey()
	legitParentProof, _ := victimParentKey.CreateProof("POST", pinnedURI, stolenRootJWT)
	legitChildProof, _ := legitChildKey.CreateProof("POST", pinnedURI, "")
	_, childTok, err := broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     stolenRootJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"tool:exec:git:status"},
		DPoPProof:        legitChildProof,
		ParentDPoPProof:  legitParentProof,
		ExchangeURI:      pinnedURI,
	})
	if err != nil {
		t.Fatalf("expected legitimate authenticated delegation to succeed, got: %v", err)
	}
	if childTok.CNF.JKT != legitChildKey.Thumbprint() {
		t.Fatalf("unexpected child CNF JKT: %s", childTok.CNF.JKT)
	}
}

// TestCNJ02_MultiHopTTLClamping verifies child tokens can never outlive their root/parent token.
func TestCNJ02_MultiHopTTLClamping(t *testing.T) {
	broker, err := NewTokenBroker(BrokerConfig{
		ExchangeURI: DefaultExchangeURI,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	parentKey, _ := GenerateDPoPKey()
	childKey, _ := GenerateDPoPKey()

	rootTok, rootJWT, err := broker.IssueRootToken(ctx, RootTokenRequest{
		Subject:        "short-lived-root",
		Scopes:         []string{"tool:exec:git:*"},
		TTL:            5 * time.Second,
		DPoPThumbprint: parentKey.Thumbprint(),
	})
	if err != nil {
		t.Fatal(err)
	}

	parentProof, _ := parentKey.CreateProof("POST", DefaultExchangeURI, rootJWT)
	childProof, _ := childKey.CreateProof("POST", DefaultExchangeURI, "")

	// Child requests 60s TTL while parent expires in 5s -> child ExpiresAt MUST be clamped <= rootTok.ExpiresAt
	resp, childTok, err := broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     rootJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"tool:exec:git:status"},
		TTL:              60 * time.Second,
		DPoPProof:        childProof,
		ParentDPoPProof:  parentProof,
	})
	if err != nil {
		t.Fatalf("ExchangeToken failed: %v", err)
	}

	if childTok.ExpiresAt > rootTok.ExpiresAt {
		t.Fatalf("CNJ-02 FAILED: child token extended TTL beyond parent (%d > %d)", childTok.ExpiresAt, rootTok.ExpiresAt)
	}
	if resp.ExpiresIn > 5 {
		t.Fatalf("CNJ-02 FAILED: response expires_in exceeded parent window: %d", resp.ExpiresIn)
	}
}

// TestCNJ02_ShardedBoundedReplayCacheConcurrency tests N=8 parallel subagent contention and shard capacity bounds.
func TestCNJ02_ShardedBoundedReplayCacheConcurrency(t *testing.T) {
	cache := NewMemoryReplayCache()
	const workers = 8
	const perWorker = 200

	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	exp := time.Now().UTC().Add(30 * time.Second)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				jti := fmt.Sprintf("agent-%d-jti-%d", id, i)
				if err := cache.CheckAndSet(jti, exp); err != nil {
					errCh <- err
					return
				}
				if err := cache.CheckAndSet(jti, exp); !errors.Is(err, ErrReplayDetected) {
					errCh <- fmt.Errorf("expected ErrReplayDetected for %s, got %v", jti, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// Verify bounded shard capacity fails closed when saturated with unexpired entries
	tinyCache := NewBoundedMemoryReplayCache(2) // 2 entries per shard * 16 shards = max 32 entries
	hitFull := false
	for i := 0; i < 40; i++ {
		err := tinyCache.CheckAndSet(fmt.Sprintf("flood-%d", i), exp)
		if errors.Is(err, ErrReplayCacheFull) {
			hitFull = true
			break
		}
	}
	if !hitFull {
		t.Fatal("CNJ-02 FAILED: bounded replay cache did not enforce per-shard capacity limit")
	}
}
