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

// TestAdversarial_WorkloadIdentityMintingAndSPIFFEBinding asserts workload identity minting,
// SPIFFE ID subject format, DPoP confirmation binding, RFC 4122 v4 UUID JTI, and strict 30s TTL.
func TestAdversarial_WorkloadIdentityMintingAndSPIFFEBinding(t *testing.T) {
	broker, err := NewTokenBroker(BrokerConfig{})
	if err != nil {
		t.Fatalf("failed initializing broker: %v", err)
	}

	dpopKey, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("failed generating dpop key: %v", err)
	}

	sessionID := "agent-subagent-88a91c"
	scopes := []string{"git:read", "issue:read", "tool:exec:safe_scan"}

	tok, tokenJWT, err := MintWorkloadIdentity(sessionID, dpopKey.PublicKey, scopes, broker.PrivateKey())
	if err != nil {
		t.Fatalf("MintWorkloadIdentity failed: %v", err)
	}

	// 1. Verify SPIFFE Subject format
	expectedSub := "spiffe://bonjo.dev/agent/" + sessionID
	if tok.Subject != expectedSub {
		t.Fatalf("expected subject %q, got %q", expectedSub, tok.Subject)
	}
	if tok.SessionID != sessionID {
		t.Fatalf("expected session ID %q, got %q", sessionID, tok.SessionID)
	}

	// 2. Verify depth 0
	if tok.Depth != 0 {
		t.Fatalf("expected depth 0, got %d", tok.Depth)
	}

	// 3. Verify strict 30s TTL window
	ttlWindow := time.Duration(tok.ExpiresAt-tok.IssuedAt) * time.Second
	if ttlWindow != DefaultTTL {
		t.Fatalf("expected strict %v TTL, got %v", DefaultTTL, ttlWindow)
	}

	// 4. Verify RFC 4122 v4 UUID JTI format
	if len(tok.JTI) != 36 || tok.JTI[8] != '-' || tok.JTI[13] != '-' || tok.JTI[18] != '-' || tok.JTI[23] != '-' {
		t.Fatalf("expected UUID format for JTI, got: %s", tok.JTI)
	}
	if tok.JTI[14] != '4' {
		t.Fatalf("expected UUID version 4 (byte 14 == '4'), got JTI: %s", tok.JTI)
	}

	// 5. Verify DPoP confirmation thumbprint
	if !tok.VerifyDPoPBinding(dpopKey.Thumbprint()) {
		t.Fatalf("DPoP confirmation binding thumbprint mismatch: tok.CNF=%s, dpopThumbprint=%s", tok.CNF.JKT, dpopKey.Thumbprint())
	}

	// 6. Verify cryptographic token signature and claims
	parsedTok, err := ParseAndVerifyToken(tokenJWT, broker.PublicKey(), time.Now().UTC())
	if err != nil {
		t.Fatalf("ParseAndVerifyToken failed: %v", err)
	}
	if parsedTok.JTI != tok.JTI || parsedTok.Subject != expectedSub {
		t.Fatalf("parsed token claim mismatch: %+v", parsedTok)
	}

	// 7. Validation errors on invalid inputs
	if _, _, err := MintWorkloadIdentity("", dpopKey.PublicKey, scopes, broker.PrivateKey()); err == nil {
		t.Fatal("expected error with empty sessionID, got nil")
	}
	if _, _, err := MintWorkloadIdentity(sessionID, nil, scopes, broker.PrivateKey()); err == nil {
		t.Fatal("expected error with nil public key, got nil")
	}
	if _, _, err := MintWorkloadIdentity(sessionID, dpopKey.PublicKey, scopes, nil); err == nil {
		t.Fatal("expected error with nil private key, got nil")
	}
}

// TestAdversarial_WorkloadIdentity30STTLExpiration asserts monotonic expiration at 30 seconds.
func TestAdversarial_WorkloadIdentity30STTLExpiration(t *testing.T) {
	broker, err := NewTokenBroker(BrokerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, _ := GenerateDPoPKey()

	tok, tokenJWT, err := MintWorkloadIdentity("sess-exp-test", dpopKey.PublicKey, []string{"read"}, broker.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	issuedTime := time.Unix(tok.IssuedAt, 0).UTC()

	// At 10s: still valid
	if _, err := ParseAndVerifyToken(tokenJWT, broker.PublicKey(), issuedTime.Add(10*time.Second)); err != nil {
		t.Fatalf("expected token to be valid at +10s, got: %v", err)
	}

	// At 29s: still valid
	if _, err := ParseAndVerifyToken(tokenJWT, broker.PublicKey(), issuedTime.Add(29*time.Second)); err != nil {
		t.Fatalf("expected token to be valid at +29s, got: %v", err)
	}

	// At 31s (past 30s TTL): MUST fail with ErrExpiredToken
	_, err = ParseAndVerifyToken(tokenJWT, broker.PublicKey(), issuedTime.Add(31*time.Second))
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken at +31s, got: %v", err)
	}
}

// TestAdversarial_InstantJTIRevocationAndForensicReason asserts sub-minute instant revocation.
func TestAdversarial_InstantJTIRevocationAndForensicReason(t *testing.T) {
	broker, err := NewTokenBroker(BrokerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, _ := GenerateDPoPKey()
	sessionID := "sess-instant-revoke"

	tok, tokenJWT, err := MintWorkloadIdentity(sessionID, dpopKey.PublicKey, []string{"git:push"}, broker.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	revStore := NewMemoryRevocationStore()
	now := time.Now().UTC()

	// 1. Initial verification succeeds
	if _, err := ParseAndVerifyTokenWithRevocation(tokenJWT, broker.PublicKey(), now, revStore); err != nil {
		t.Fatalf("initial verification should succeed: %v", err)
	}

	// 2. Instant JTI revocation with reason
	reason := "Argus tripwire: detected unauthorized slopsquatted package execution"
	exp := now.Add(24 * time.Hour)
	if err := revStore.RevokeWithReason(tok.JTI, exp, reason); err != nil {
		t.Fatalf("RevokeWithReason failed: %v", err)
	}

	// 3. Verification immediately fails closed with ErrTokenRevoked
	_, err = ParseAndVerifyTokenWithRevocation(tokenJWT, broker.PublicKey(), now, revStore)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked after JTI revocation, got: %v", err)
	}

	// 4. Other token in different session is not revoked
	otherTok, otherJWT, err := MintWorkloadIdentity("other-sess", dpopKey.PublicKey, []string{"read"}, broker.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if otherTok.JTI == tok.JTI {
		t.Fatal("expected distinct JTIs")
	}
	if _, err := ParseAndVerifyTokenWithRevocation(otherJWT, broker.PublicKey(), now, revStore); err != nil {
		t.Fatalf("unrelated token should not be revoked: %v", err)
	}

	// 5. Session-wide revocation also revokes all tokens for that session
	if err := revStore.RevokeSession("other-sess", exp); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
	_, err = ParseAndVerifyTokenWithRevocation(otherJWT, broker.PublicKey(), now, revStore)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked after session revocation, got: %v", err)
	}
}
