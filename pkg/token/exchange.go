package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
)

const (
	// GrantTypeTokenExchange is the standard RFC 8693 token exchange grant identifier.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// TokenTypeAccessToken is the standard RFC 8693 token type identifier.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	// DefaultExchangeURI is the canonical DPoP HTU endpoint for token exchange when not overridden.
	DefaultExchangeURI = "https://broker.local/token"
)

var (
	// ErrInvalidGrantType indicates non-RFC 8693 grant type.
	ErrInvalidGrantType = errors.New("unsupported grant type: expected urn:ietf:params:oauth:grant-type:token-exchange")
	// ErrInvalidTokenType indicates non-access token type.
	ErrInvalidTokenType = errors.New("unsupported token type: expected urn:ietf:params:oauth:token-type:access_token")
	// ErrMissingDPoPProof indicates required DPoP proof was omitted.
	ErrMissingDPoPProof = errors.New("missing mandatory dpop proof in exchange request")
	// ErrTTLTooLarge indicates requested TTL exceeds maximum permitted.
	ErrTTLTooLarge = errors.New("requested token TTL exceeds 60s maximum policy limit")
)

// TokenExchangeRequest encapsulates an RFC 8693 Token Exchange payload.
type TokenExchangeRequest struct {
	GrantType          string        `json:"grant_type"`
	SubjectToken       string        `json:"subject_token"`
	SubjectTokenType   string        `json:"subject_token_type"`
	RequestedTokenType string        `json:"requested_token_type,omitempty"`
	Subject            string        `json:"subject,omitempty"` // Child agent identity
	Audience           string        `json:"audience,omitempty"`
	Scope              []string      `json:"scope"`
	TTL                time.Duration `json:"ttl,omitempty"`
	DPoPProof          string        `json:"dpop_proof"`
	ParentDPoPProof    string        `json:"parent_dpop_proof,omitempty"` // Proves possession of parentToken.CNF.JKT when delegating to a distinct child key
	ExchangeURI        string        `json:"exchange_uri,omitempty"`      // For DPoP HTU validation
}

// TokenExchangeResponse represents an RFC 8693 Token Exchange response.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"` // "DPoP"
	ExpiresIn       int64  `json:"expires_in"` // Seconds
	Scope           string `json:"scope"`
}

// TokenBroker manages root token issuance and RFC 8693 Token Exchange with DPoP binding.
type TokenBroker struct {
	brokerPrivKey ed25519.PrivateKey
	brokerPubKey  ed25519.PublicKey
	replayCache   ReplayCache
	issuer        string
	exchangeURI   string
	defaultTTL    time.Duration
}

// BrokerConfig holds configuration options for TokenBroker.
type BrokerConfig struct {
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	ReplayCache ReplayCache
	Issuer      string
	ExchangeURI string
	DefaultTTL  time.Duration
}

// NewTokenBroker initializes a new TokenBroker instance.
func NewTokenBroker(cfg BrokerConfig) (*TokenBroker, error) {
	if cfg.PrivateKey == nil || cfg.PublicKey == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate broker root key: %w", err)
		}
		cfg.PublicKey = pub
		cfg.PrivateKey = priv
	}

	if cfg.ReplayCache == nil {
		cfg.ReplayCache = NewMemoryReplayCache()
	}

	if cfg.Issuer == "" {
		cfg.Issuer = DefaultIssuer
	}

	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = DefaultTTL
	}

	return &TokenBroker{
		brokerPrivKey: cfg.PrivateKey,
		brokerPubKey:  cfg.PublicKey,
		replayCache:   cfg.ReplayCache,
		issuer:        cfg.Issuer,
		exchangeURI:   strings.TrimSpace(cfg.ExchangeURI),
		defaultTTL:    cfg.DefaultTTL,
	}, nil
}

// PublicKey returns the broker's public key for signature verification.
func (b *TokenBroker) PublicKey() ed25519.PublicKey {
	return b.brokerPubKey
}

// ReplayCache returns the underlying replay cache.
func (b *TokenBroker) ReplayCache() ReplayCache {
	return b.replayCache
}

// RootTokenRequest contains parameters to issue an initial root parent token.
type RootTokenRequest struct {
	Subject        string
	SessionID      string
	Audience       string
	Scopes         []string
	TTL            time.Duration
	DPoPThumbprint string
}

// IssueRootToken issues a new root-level task token bound to a client DPoP key.
func (b *TokenBroker) IssueRootToken(ctx context.Context, req RootTokenRequest) (*TaskToken, string, error) {
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	default:
	}

	if req.DPoPThumbprint == "" {
		return nil, "", errors.New("dpop thumbprint is required for token binding")
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = b.defaultTTL
	}
	if ttl > MaxAllowedTTL {
		return nil, "", fmt.Errorf("%w: %v > %v", ErrTTLTooLarge, ttl, MaxAllowedTTL)
	}

	scopeSet, err := attenuation.NewScopeSet(req.Scopes...)
	if err != nil {
		return nil, "", fmt.Errorf("invalid root scopes: %w", err)
	}

	jti, err := GenerateRandomJTI()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token jti: %w", err)
	}

	now := time.Now().UTC()
	aud := req.Audience
	if aud == "" {
		aud = DefaultAudience
	}

	token := &TaskToken{
		JTI:       jti,
		Issuer:    b.issuer,
		Subject:   req.Subject,
		SessionID: req.SessionID,
		Audience:  aud,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Scope:     scopeSet.Strings(),
		CNF:       CNF{JKT: req.DPoPThumbprint},
		Depth:     1,
	}

	signed, err := token.Sign(b.brokerPrivKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign root token: %w", err)
	}

	return token, signed, nil
}

// ExchangeToken processes an RFC 8693 Token Exchange request, enforcing:
// 1. DPoP proof validation from the requesting child agent (with pinned/non-empty HTU)
// 2. Parent token signature & expiration check (30s TTL)
// 3. Proof-of-Possession of parentToken.CNF.JKT (preventing stolen SubjectToken bearer replay)
// 4. Strict scope attenuation: ChildScope = ParentScope ∩ RequestedScope (superset denied)
// 5. Monotonic expiration clamping: childToken.ExpiresAt <= parentToken.ExpiresAt
// 6. Token binding to child's ephemeral DPoP thumbprint
func (b *TokenBroker) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (*TokenExchangeResponse, *TaskToken, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	// 1. Verify standard grant type
	if req.GrantType != GrantTypeTokenExchange {
		return nil, nil, fmt.Errorf("%w: got '%s'", ErrInvalidGrantType, req.GrantType)
	}

	if req.SubjectTokenType != TokenTypeAccessToken {
		return nil, nil, fmt.Errorf("%w: got '%s'", ErrInvalidTokenType, req.SubjectTokenType)
	}

	if req.DPoPProof == "" {
		return nil, nil, ErrMissingDPoPProof
	}

	now := time.Now().UTC()

	// Resolve canonical HTU for DPoP verification
	expectedURI := b.exchangeURI
	if expectedURI != "" {
		if req.ExchangeURI != "" && req.ExchangeURI != expectedURI {
			return nil, nil, fmt.Errorf("%w: got exchange_uri '%s', expected '%s'", ErrURIMismatch, req.ExchangeURI, expectedURI)
		}
	} else if strings.TrimSpace(req.ExchangeURI) != "" {
		expectedURI = strings.TrimSpace(req.ExchangeURI)
	} else {
		expectedURI = DefaultExchangeURI
	}

	// 2. Validate DPoP proof presented by the requesting sub-agent
	dpopPayload, dpopJWK, err := ValidateProof(
		req.DPoPProof,
		"POST",
		expectedURI,
		"", // Child proof binds the new child key; if ATH is supplied, checked below on self-attenuation
		30*time.Second,
		b.replayCache,
		now,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dpop proof verification failed: %w", err)
	}

	childDPoPThumbprint := dpopJWK.Thumbprint()

	// 3. Verify parent subject token
	parentToken, err := ParseAndVerifyToken(req.SubjectToken, b.brokerPubKey, now)
	if err != nil {
		return nil, nil, fmt.Errorf("subject token verification failed: %w", err)
	}

	// 4. Enforce Proof-of-Possession of parent token's bound DPoP key (CNJ-02)
	if parentToken.CNF.JKT != "" {
		if req.ParentDPoPProof != "" {
			_, parentJWK, err := ValidateProof(
				req.ParentDPoPProof,
				"POST",
				expectedURI,
				req.SubjectToken, // Require RFC 9449 ath binding to SubjectToken
				30*time.Second,
				b.replayCache,
				now,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("parent dpop proof verification failed: %w", err)
			}
			if !parentToken.VerifyDPoPBinding(parentJWK.Thumbprint()) {
				return nil, nil, fmt.Errorf("%w: parent dpop proof key does not match subject_token cnf.jkt", ErrDPoPBindingMismatch)
			}
		} else {
			// Self-attenuation: only permitted if child DPoP key IS the parent DPoP key
			if !parentToken.VerifyDPoPBinding(childDPoPThumbprint) {
				return nil, nil, fmt.Errorf("%w: missing parent dpop proof for subject_token bound to cnf.jkt", ErrDPoPBindingMismatch)
			}
			if dpopPayload.ATH != "" && dpopPayload.ATH != ComputeATH(req.SubjectToken) {
				return nil, nil, ErrATHMismatch
			}
		}
	}

	if parentToken.Depth >= attenuation.MaxDelegationDepth {
		return nil, nil, fmt.Errorf("%w: current depth %d", attenuation.ErrMaxDepthExceeded, parentToken.Depth)
	}

	// 5. Perform scope attenuation: ChildScope ⊆ ParentScope
	parentScopeSet, err := parentToken.ScopeSet()
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing parent scopes: %w", err)
	}

	requestedScopeSet, err := attenuation.NewScopeSet(req.Scope...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing requested scopes: %w", err)
	}

	attenuatedScopeSet, err := attenuation.Attenuate(parentScopeSet, requestedScopeSet)
	if err != nil {
		return nil, nil, fmt.Errorf("attenuation denied: %w", err)
	}

	// 6. Enforce strict 30s TTL (up to MaxAllowedTTL) AND clamp strictly <= parentToken.ExpiresAt
	ttl := req.TTL
	if ttl == 0 {
		ttl = b.defaultTTL
	}
	if ttl > MaxAllowedTTL {
		return nil, nil, fmt.Errorf("%w: %v > %v", ErrTTLTooLarge, ttl, MaxAllowedTTL)
	}

	childExpiresAt := now.Add(ttl).Unix()
	if childExpiresAt > parentToken.ExpiresAt {
		childExpiresAt = parentToken.ExpiresAt
	}
	if childExpiresAt <= now.Unix() {
		return nil, nil, ErrExpiredToken
	}

	childJTI, err := GenerateRandomJTI()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate child token jti: %w", err)
	}

	childSubject := req.Subject
	if childSubject == "" {
		childSubject = fmt.Sprintf("%s:delegated:%s", parentToken.Subject, childJTI[:8])
	}

	childAudience := req.Audience
	if childAudience == "" {
		childAudience = parentToken.Audience
	}

	childToken := &TaskToken{
		JTI:           childJTI,
		Issuer:        b.issuer,
		Subject:       childSubject,
		SessionID:     parentToken.SessionID,
		Audience:      childAudience,
		IssuedAt:      now.Unix(),
		ExpiresAt:     childExpiresAt,
		Scope:         attenuatedScopeSet.Strings(),
		CNF:           CNF{JKT: childDPoPThumbprint},
		ParentTokenID: parentToken.JTI,
		Depth:         parentToken.Depth + 1,
	}

	signedChildToken, err := childToken.Sign(b.brokerPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign child token: %w", err)
	}

	response := &TokenExchangeResponse{
		AccessToken:     signedChildToken,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "DPoP",
		ExpiresIn:       childExpiresAt - now.Unix(),
		Scope:           strings.Join(attenuatedScopeSet.Strings(), " "),
	}

	return response, childToken, nil
}
