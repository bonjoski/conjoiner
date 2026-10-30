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
	GrantType          string   `json:"grant_type"`
	SubjectToken       string   `json:"subject_token"`
	SubjectTokenType   string   `json:"subject_token_type"`
	RequestedTokenType string   `json:"requested_token_type,omitempty"`
	Subject            string   `json:"subject,omitempty"` // Child agent identity
	Audience           string   `json:"audience,omitempty"`
	Scope              []string `json:"scope"`
	TTL                time.Duration `json:"ttl,omitempty"`
	DPoPProof          string   `json:"dpop_proof"`
	ExchangeURI        string   `json:"exchange_uri,omitempty"` // For DPoP HTU validation
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
	defaultTTL    time.Duration
}

// BrokerConfig holds configuration options for TokenBroker.
type BrokerConfig struct {
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	ReplayCache ReplayCache
	Issuer      string
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
	Subject       string
	Audience      string
	Scopes        []string
	TTL           time.Duration
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
// 1. DPoP proof validation from the requesting child agent
// 2. Parent token signature & expiration check (30s TTL)
// 3. Strict scope attenuation: ChildScope = ParentScope ∩ RequestedScope (superset denied)
// 4. Token binding to child's ephemeral DPoP thumbprint
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

	// 2. Validate DPoP proof presented by the requesting sub-agent
	expectedURI := req.ExchangeURI
	dpopPayload, dpopJWK, err := ValidateProof(
		req.DPoPProof,
		"POST",
		expectedURI,
		"", // No access token required during initial token exchange call
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

	if parentToken.Depth >= attenuation.MaxDelegationDepth {
		return nil, nil, fmt.Errorf("%w: current depth %d", attenuation.ErrMaxDepthExceeded, parentToken.Depth)
	}

	// 4. Perform scope attenuation: ChildScope ⊆ ParentScope
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

	// 5. Enforce strict 30s TTL (or requested TTL up to MaxAllowedTTL)
	ttl := req.TTL
	if ttl == 0 {
		ttl = b.defaultTTL
	}
	if ttl > MaxAllowedTTL {
		return nil, nil, fmt.Errorf("%w: %v > %v", ErrTTLTooLarge, ttl, MaxAllowedTTL)
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
		Audience:      childAudience,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(ttl).Unix(),
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
		ExpiresIn:       int64(ttl.Seconds()),
		Scope:           strings.Join(attenuatedScopeSet.Strings(), " "),
	}

	_ = dpopPayload // consumed

	return response, childToken, nil
}
