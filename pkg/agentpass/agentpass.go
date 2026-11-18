package agentpass

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
	"github.com/bonjoski/conjoiner/pkg/token"
)

var (
	// ErrExpiredPass indicates the AgentPass has exceeded its validity lifetime.
	ErrExpiredPass = errors.New("agentpass has expired")
	// ErrMaxDelegationDepthExceeded indicates child delegation exceeds the allowed maximum.
	ErrMaxDelegationDepthExceeded = errors.New("maximum subagent delegation depth exceeded")
	// ErrInvalidPassSignature indicates cryptographic signature verification failed.
	ErrInvalidPassSignature = errors.New("invalid agentpass signature")
	// ErrMalformedPass indicates malformed compact JWS string.
	ErrMalformedPass = errors.New("malformed agentpass token")
	// ErrUnauthorizedSupervisor indicates the pass supervisor is missing or invalid.
	ErrUnauthorizedSupervisor = errors.New("human supervisor identity is required")
	// ErrActionNotPermitted indicates the requested tool action is outside the pass scope.
	ErrActionNotPermitted = errors.New("tool action not permitted under active agentpass scope")
	// ErrHardwareRequired indicates hardware presence or biometric elevation is required.
	ErrHardwareRequired = errors.New("action requires hardware presence / biometric attestation")
)

const (
	// DefaultPassLifetime is the standard validity for an AgentPass session (1 hour).
	DefaultPassLifetime = 1 * time.Hour
	// MaxPassLifetime is the absolute ceiling for an AgentPass session (8 hours).
	MaxPassLifetime = 8 * time.Hour
	// DefaultMaxDepth is the default maximum subagent delegation depth.
	DefaultMaxDepth = 3
	// DefaultToolTokenTTL is the lifetime of minted single-tool execution tokens (30 seconds).
	DefaultToolTokenTTL = 30 * time.Second
)

// AgentPassHeader defines the compact JWS header.
type AgentPassHeader struct {
	Typ string `json:"typ"` // "agentpass+jwt"
	Alg string `json:"alg"` // "EdDSA"
}

// AgentPass represents an accountable, human-supervised capability pass for autonomous agents.
type AgentPass struct {
	PassID          string   `json:"pass_id"`                  // Unique Pass JTI
	AgentID         string   `json:"agent_id"`                 // Accountable agent subject
	HumanSupervisor string   `json:"human_supervisor"`         // Accountable human supervisor (e.g. user@org.dev)
	Scope           []string `json:"scope"`                    // Attenuated active scope set
	RootScope       []string `json:"root_scope"`               // Original root granted scope
	SessionID       string   `json:"session_id"`               // Parent session identifier
	ParentPassID    string   `json:"parent_pass_id,omitempty"` // Immediate parent pass ID
	DelegationDepth int      `json:"delegation_depth"`         // Current delegation tier (0 = root)
	MaxDepth        int      `json:"max_depth"`                // Max allowed delegation depth
	WorktreePath    string   `json:"worktree_path,omitempty"`  // Bound workspace worktree
	DPoPThumbprint  string   `json:"dpop_jkt"`                 // Bound RFC 7638 Ed25519 thumbprint
	RequireHardware bool     `json:"require_hardware"`         // Whether high-risk actions require Locksmith presence
	IssuedAt        int64    `json:"iat"`                      // Issued at Unix timestamp
	ExpiresAt       int64    `json:"exp"`                      // Expires at Unix timestamp
	TokenTTL        int64    `json:"token_ttl"`                // Lifetime of minted tool tokens in seconds
}

// ScopeSet returns the parsed attenuation.ScopeSet for the pass.
func (p *AgentPass) ScopeSet() (attenuation.ScopeSet, error) {
	return attenuation.NewScopeSet(p.Scope...)
}

// IsExpired reports whether the pass is expired at the given time.
func (p *AgentPass) IsExpired(now time.Time) bool {
	return now.Unix() > p.ExpiresAt
}

// VerifyDPoPBinding confirms that the presented thumbprint matches the bound DPoP key.
func (p *AgentPass) VerifyDPoPBinding(expectedThumbprint string) bool {
	if p.DPoPThumbprint == "" || expectedThumbprint == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p.DPoPThumbprint), []byte(expectedThumbprint)) == 1
}

// Sign serializes and cryptographically signs the AgentPass using the broker's Ed25519 key.
func (p *AgentPass) Sign(brokerPrivKey ed25519.PrivateKey) (string, error) {
	header := AgentPassHeader{
		Typ: "agentpass+jwt",
		Alg: "EdDSA",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed marshaling agentpass header: %w", err)
	}

	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed marshaling agentpass payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	signature := ed25519.Sign(brokerPrivKey, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + sigB64, nil
}

// Verify verifies the compact JWS string, signature, and expiration.
func Verify(passToken string, brokerPubKey ed25519.PublicKey, now time.Time) (*AgentPass, error) {
	parts := strings.Split(passToken, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedPass
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header base64: %v", ErrMalformedPass, err)
	}

	var header AgentPassHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: invalid header json: %v", ErrMalformedPass, err)
	}

	if header.Typ != "agentpass+jwt" || header.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: unsupported header parameters", ErrMalformedPass)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature base64: %v", ErrMalformedPass, err)
	}

	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(brokerPubKey, []byte(signingInput), sigBytes) {
		return nil, ErrInvalidPassSignature
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload base64: %v", ErrMalformedPass, err)
	}

	var pass AgentPass
	if err := json.Unmarshal(payloadJSON, &pass); err != nil {
		return nil, fmt.Errorf("%w: invalid payload json: %v", ErrMalformedPass, err)
	}

	if pass.IsExpired(now) {
		return nil, ErrExpiredPass
	}

	if pass.HumanSupervisor == "" {
		return nil, ErrUnauthorizedSupervisor
	}

	return &pass, nil
}

// IssueOptions configures root AgentPass issuance.
type IssueOptions struct {
	AgentID         string
	HumanSupervisor string
	Scope           []string
	SessionID       string
	WorktreePath    string
	DPoPThumbprint  string
	RequireHardware bool
	Lifetime        time.Duration
	MaxDepth        int
	TokenTTL        time.Duration
}

// IssueRootPass creates and signs a new root AgentPass tied to an accountable human supervisor.
func IssueRootPass(opts IssueOptions, brokerPrivKey ed25519.PrivateKey, now time.Time) (*AgentPass, string, error) {
	if strings.TrimSpace(opts.HumanSupervisor) == "" {
		return nil, "", ErrUnauthorizedSupervisor
	}

	scopeSet, err := attenuation.NewScopeSet(opts.Scope...)
	if err != nil {
		return nil, "", fmt.Errorf("invalid root scope: %w", err)
	}
	if scopeSet.IsEmpty() {
		return nil, "", errors.New("agentpass requires at least one granted scope")
	}

	lifetime := opts.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultPassLifetime
	}
	if lifetime > MaxPassLifetime {
		lifetime = MaxPassLifetime
	}

	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}

	tokenTTL := opts.TokenTTL
	if tokenTTL <= 0 {
		tokenTTL = DefaultToolTokenTTL
	}

	agentID := opts.AgentID
	if agentID == "" {
		raw := make([]byte, 8)
		_, _ = rand.Read(raw)
		agentID = "agent:" + hex.EncodeToString(raw)
	}

	sessionID := opts.SessionID
	if sessionID == "" {
		raw := make([]byte, 12)
		_, _ = rand.Read(raw)
		sessionID = "sess-" + hex.EncodeToString(raw)
	}

	passIDBytes := make([]byte, 16)
	_, _ = rand.Read(passIDBytes)
	passID := "pass_" + hex.EncodeToString(passIDBytes)

	pass := &AgentPass{
		PassID:          passID,
		AgentID:         agentID,
		HumanSupervisor: opts.HumanSupervisor,
		Scope:           scopeSet.Strings(),
		RootScope:       scopeSet.Strings(),
		SessionID:       sessionID,
		DelegationDepth: 0,
		MaxDepth:        maxDepth,
		WorktreePath:    opts.WorktreePath,
		DPoPThumbprint:  opts.DPoPThumbprint,
		RequireHardware: opts.RequireHardware,
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(lifetime).Unix(),
		TokenTTL:        int64(tokenTTL.Seconds()),
	}

	signed, err := pass.Sign(brokerPrivKey)
	if err != nil {
		return nil, "", err
	}

	return pass, signed, nil
}

// AttenuateOptions configures child subagent pass derivation.
type AttenuateOptions struct {
	RequestedScope []string
	ChildAgentID   string
	ChildDPoPThumb string
	Lifetime       time.Duration
}

// AttenuatePass derives a strictly subsetted, attenuated AgentPass for a child subagent.
// It mathematically enforces ChildScope = ParentScope ∩ RequestedScope.
// If any requested scope expands privileges beyond the parent pass, it strictly rejects.
func AttenuatePass(parent *AgentPass, opts AttenuateOptions, brokerPrivKey ed25519.PrivateKey, now time.Time) (*AgentPass, string, error) {
	if parent.IsExpired(now) {
		return nil, "", ErrExpiredPass
	}

	if parent.DelegationDepth >= parent.MaxDepth {
		return nil, "", fmt.Errorf("%w: current depth %d reaches ceiling %d", ErrMaxDelegationDepthExceeded, parent.DelegationDepth, parent.MaxDepth)
	}

	parentScopes, err := parent.ScopeSet()
	if err != nil {
		return nil, "", fmt.Errorf("malformed parent scope set: %w", err)
	}

	requestedScopes, err := attenuation.NewScopeSet(opts.RequestedScope...)
	if err != nil {
		return nil, "", fmt.Errorf("invalid requested scope: %w", err)
	}
	if requestedScopes.IsEmpty() {
		return nil, "", errors.New("attenuated pass requires at least one requested scope")
	}

	// Strict monotonic attenuation check: ChildScope ⊆ ParentScope
	attenuatedScopes, err := attenuation.Attenuate(parentScopes, requestedScopes)
	if err != nil {
		return nil, "", err
	}

	childAgentID := opts.ChildAgentID
	if childAgentID == "" {
		raw := make([]byte, 8)
		_, _ = rand.Read(raw)
		childAgentID = fmt.Sprintf("%s:sub:%s", parent.AgentID, hex.EncodeToString(raw))
	}

	// Calculate child expiration: min(now + requestedLifetime, parent.ExpiresAt)
	childExp := now.Add(DefaultPassLifetime).Unix()
	if opts.Lifetime > 0 {
		childExp = now.Add(opts.Lifetime).Unix()
	}
	if childExp > parent.ExpiresAt {
		childExp = parent.ExpiresAt
	}

	passIDBytes := make([]byte, 16)
	_, _ = rand.Read(passIDBytes)
	childPassID := "pass_" + hex.EncodeToString(passIDBytes)

	childPass := &AgentPass{
		PassID:          childPassID,
		AgentID:         childAgentID,
		HumanSupervisor: parent.HumanSupervisor,
		Scope:           attenuatedScopes.Strings(),
		RootScope:       parent.RootScope,
		SessionID:       parent.SessionID,
		ParentPassID:    parent.PassID,
		DelegationDepth: parent.DelegationDepth + 1,
		MaxDepth:        parent.MaxDepth,
		WorktreePath:    parent.WorktreePath,
		DPoPThumbprint:  opts.ChildDPoPThumb,
		RequireHardware: parent.RequireHardware,
		IssuedAt:        now.Unix(),
		ExpiresAt:       childExp,
		TokenTTL:        parent.TokenTTL,
	}

	signed, err := childPass.Sign(brokerPrivKey)
	if err != nil {
		return nil, "", err
	}

	return childPass, signed, nil
}

// Permits checks if the given tool action scope is authoritatively covered by the pass scope.
func (p *AgentPass) Permits(toolAction string) (bool, error) {
	scopeSet, err := p.ScopeSet()
	if err != nil {
		return false, fmt.Errorf("failed parsing pass scope: %w", err)
	}
	actionScope, err := attenuation.ParseScope(toolAction)
	if err != nil {
		return false, fmt.Errorf("invalid tool action scope: %w", err)
	}
	return scopeSet.Contains(actionScope), nil
}

// MintToolToken issues a 30-second single-tool execution TaskToken for an authenticated AgentPass.
func MintToolToken(pass *AgentPass, toolAction string, brokerPrivKey ed25519.PrivateKey, now time.Time) (*token.TaskToken, string, error) {
	if pass.IsExpired(now) {
		return nil, "", ErrExpiredPass
	}

	scopeSet, err := pass.ScopeSet()
	if err != nil {
		return nil, "", fmt.Errorf("failed parsing pass scope: %w", err)
	}

	actionScope, err := attenuation.ParseScope(toolAction)
	if err != nil {
		return nil, "", fmt.Errorf("invalid tool action scope: %w", err)
	}

	if !scopeSet.Contains(actionScope) {
		return nil, "", fmt.Errorf("%w: action '%s' is not covered by pass scope [%s]",
			ErrActionNotPermitted, toolAction, strings.Join(pass.Scope, ", "))
	}

	ttl := time.Duration(pass.TokenTTL) * time.Second
	if ttl <= 0 {
		ttl = DefaultToolTokenTTL
	}

	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	jti := "tok_" + hex.EncodeToString(jtiBytes)

	taskTok := &token.TaskToken{
		JTI:       jti,
		Issuer:    token.DefaultIssuer,
		Subject:   pass.AgentID,
		SessionID: pass.SessionID,
		Audience:  token.DefaultAudience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Scope:     []string{actionScope.Raw},
		CNF: token.CNF{
			JKT: pass.DPoPThumbprint,
		},
		ParentTokenID: pass.PassID,
		Depth:         pass.DelegationDepth,
	}

	signedJWT, err := taskTok.Sign(brokerPrivKey)
	if err != nil {
		return nil, "", err
	}

	return taskTok, signedJWT, nil
}

// PassSessionStore provides in-memory thread-safe caching of active AgentPass sessions.
type PassSessionStore struct {
	mu     sync.RWMutex
	passes map[string]*AgentPass
}

// NewPassSessionStore initializes an empty in-memory store.
func NewPassSessionStore() *PassSessionStore {
	return &PassSessionStore{
		passes: make(map[string]*AgentPass),
	}
}

// Store registers a pass.
func (s *PassSessionStore) Store(pass *AgentPass) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passes[pass.PassID] = pass
}

// Get retrieves a pass by ID.
func (s *PassSessionStore) Get(passID string) (*AgentPass, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.passes[passID]
	return p, ok
}

// Revoke removes a pass and invalidates its session.
func (s *PassSessionStore) Revoke(passID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.passes, passID)
}
