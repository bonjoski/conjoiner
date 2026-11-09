package token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
)

// TestTokenExchangeExpiry satisfies deliverable: test_token_exchange_expiry
func TestTokenExchangeExpiry(t *testing.T) {
	t.Run("test_token_exchange_expiry", func(t *testing.T) {
		broker, err := NewTokenBroker(BrokerConfig{})
		if err != nil {
			t.Fatalf("failed to initialize broker: %v", err)
		}

		ctx := context.Background()
		parentDPoP, _ := GenerateDPoPKey()
		childDPoP, _ := GenerateDPoPKey()

		// 1. Issue root parent token with strict 30s TTL
		rootToken, rootTokenJWT, err := broker.IssueRootToken(ctx, RootTokenRequest{
			Subject:        "parent-agent",
			Scopes:         []string{"fs:read:/tmp/workspace", "tool:exec:git:*"},
			TTL:            30 * time.Second,
			DPoPThumbprint: parentDPoP.Thumbprint(),
		})
		if err != nil {
			t.Fatalf("failed to issue root token: %v", err)
		}

		if rootToken.ExpiresAt-rootToken.IssuedAt != 30 {
			t.Fatalf("expected 30s TTL, got %d seconds", rootToken.ExpiresAt-rootToken.IssuedAt)
		}

		now := time.Now().UTC()

		// Verify token is valid right now
		parsedToken, err := ParseAndVerifyToken(rootTokenJWT, broker.PublicKey(), now)
		if err != nil {
			t.Fatalf("expected token verification to succeed, got: %v", err)
		}
		if parsedToken.JTI != rootToken.JTI {
			t.Errorf("expected token JTI %s, got %s", rootToken.JTI, parsedToken.JTI)
		}

		// 2. Advance time past 30s window (31 seconds later)
		pastExpiry := now.Add(31 * time.Second)
		_, err = ParseAndVerifyToken(rootTokenJWT, broker.PublicKey(), pastExpiry)
		if err == nil {
			t.Fatalf("expected token to be expired after 30s TTL, got nil error")
		}
		if !errors.Is(err, ErrExpiredToken) {
			t.Errorf("expected ErrExpiredToken, got: %v", err)
		}

		// 3. Attempt token exchange with an expired parent token -> must fail
		childProof, err := childDPoP.CreateProof("POST", "https://broker.local/exchange", "")
		if err != nil {
			t.Fatalf("failed creating child dpop proof: %v", err)
		}

		// Wait 1 millisecond or use expired token directly
		// Let's create an expired parent token string manually to verify exchange denial
		expiredParentToken := *rootToken
		expiredParentToken.IssuedAt = now.Add(-60 * time.Second).Unix()
		expiredParentToken.ExpiresAt = now.Add(-30 * time.Second).Unix()
		expiredParentJWT, _ := expiredParentToken.Sign(broker.brokerPrivKey)

		_, _, err = broker.ExchangeToken(ctx, TokenExchangeRequest{
			GrantType:        GrantTypeTokenExchange,
			SubjectToken:     expiredParentJWT,
			SubjectTokenType: TokenTypeAccessToken,
			Scope:            []string{"fs:read:/tmp/workspace/src"},
			DPoPProof:        childProof,
			ExchangeURI:      "https://broker.local/exchange",
		})
		if err == nil {
			t.Fatalf("expected token exchange with expired parent token to fail, got nil")
		}
		if !errors.Is(err, ErrExpiredToken) {
			t.Errorf("expected ErrExpiredToken in exchange rejection, got: %v", err)
		}
	})
}

func TestTokenExchangeAttenuationAndBinding(t *testing.T) {
	broker, err := NewTokenBroker(BrokerConfig{})
	if err != nil {
		t.Fatalf("failed to initialize broker: %v", err)
	}

	ctx := context.Background()
	parentDPoP, _ := GenerateDPoPKey()
	childDPoP, _ := GenerateDPoPKey()

	_, rootTokenJWT, err := broker.IssueRootToken(ctx, RootTokenRequest{
		Subject:        "parent-agent",
		Scopes:         []string{"fs:read:/tmp/workspace", "tool:exec:git:status"},
		TTL:            30 * time.Second,
		DPoPThumbprint: parentDPoP.Thumbprint(),
	})
	if err != nil {
		t.Fatalf("failed issuing root token: %v", err)
	}

	parentProof1, err := parentDPoP.CreateProof("POST", "https://broker.local/exchange", rootTokenJWT)
	if err != nil {
		t.Fatalf("failed creating parent dpop proof: %v", err)
	}
	childProof, err := childDPoP.CreateProof("POST", "https://broker.local/exchange", "")
	if err != nil {
		t.Fatalf("failed creating child dpop proof: %v", err)
	}

	// 1. Success case: child requests valid subset with parent PoP
	resp, childToken, err := broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     rootTokenJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"fs:read:/tmp/workspace/pkg"},
		DPoPProof:        childProof,
		ParentDPoPProof:  parentProof1,
		ExchangeURI:      "https://broker.local/exchange",
	})
	if err != nil {
		t.Fatalf("expected successful exchange, got: %v", err)
	}

	if resp.TokenType != "DPoP" {
		t.Errorf("expected token_type DPoP, got %s", resp.TokenType)
	}
	if resp.ExpiresIn <= 0 || resp.ExpiresIn > 30 {
		t.Errorf("expected expires_in in (0, 30], got %d", resp.ExpiresIn)
	}

	// Check child token DPoP binding
	if childToken.CNF.JKT != childDPoP.Thumbprint() {
		t.Errorf("child token must be bound to child's DPoP thumbprint, got %s expected %s",
			childToken.CNF.JKT, childDPoP.Thumbprint())
	}
	if childToken.Depth != 2 {
		t.Errorf("expected depth 2, got %d", childToken.Depth)
	}

	// 2. Superset denial case: child requests privilege expansion (fs:write)
	parentProof2, _ := parentDPoP.CreateProof("POST", "https://broker.local/exchange", rootTokenJWT)
	childProof2, _ := childDPoP.CreateProof("POST", "https://broker.local/exchange", "")
	_, _, err = broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     rootTokenJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"fs:write:/tmp/workspace"}, // Parent is read only
		DPoPProof:        childProof2,
		ParentDPoPProof:  parentProof2,
		ExchangeURI:      "https://broker.local/exchange",
	})
	if err == nil {
		t.Fatalf("expected superset scope to be denied, got nil error")
	}
	if !errors.Is(err, attenuation.ErrSupersetScopeDenied) {
		t.Errorf("expected ErrSupersetScopeDenied, got: %v", err)
	}

	// 3. TTL too large (>60s)
	parentProof3, _ := parentDPoP.CreateProof("POST", "https://broker.local/exchange", rootTokenJWT)
	childProof3, _ := childDPoP.CreateProof("POST", "https://broker.local/exchange", "")
	_, _, err = broker.ExchangeToken(ctx, TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     rootTokenJWT,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            []string{"fs:read:/tmp/workspace/pkg"},
		TTL:              120 * time.Second,
		DPoPProof:        childProof3,
		ParentDPoPProof:  parentProof3,
		ExchangeURI:      "https://broker.local/exchange",
	})
	if err == nil || !errors.Is(err, ErrTTLTooLarge) {
		t.Errorf("expected ErrTTLTooLarge, got: %v", err)
	}
}
