package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
)

var (
	// ErrExpiredToken indicates the token has expired.
	ErrExpiredToken = errors.New("task token has expired (exceeded 30s TTL window)")
	// ErrInvalidTokenSignature indicates the token signature verification failed.
	ErrInvalidTokenSignature = errors.New("invalid task token signature")
	// ErrMalformedToken indicates token string does not conform to 3-part compact JWT format.
	ErrMalformedToken = errors.New("malformed task token JWT")
	// ErrDPoPBindingMismatch indicates the token cnf.jkt thumbprint does not match the DPoP proof key.
	ErrDPoPBindingMismatch = errors.New("dpop key binding mismatch: token is not bound to the presented dpop key")
	// ErrTokenNotYetValid indicates token issued at is in the future.
	ErrTokenNotYetValid = errors.New("token is not yet valid")
	// ErrTokenRevoked indicates the task token, session, or subject has been explicitly revoked.
	ErrTokenRevoked = errors.New("task token or session has been revoked")
)

const (
	// DefaultTTL is the strict NIST ephemeral token TTL (30 seconds).
	DefaultTTL = 30 * time.Second
	// MaxAllowedTTL is the absolute ceiling for ephemeral agent tokens (60 seconds).
	MaxAllowedTTL = 60 * time.Second
	// DefaultIssuer is the default issuer tag for Conjoiner.
	DefaultIssuer = "conjoiner:broker"
	// DefaultAudience is the default target audience for tool invocation.
	DefaultAudience = "conjoiner:gateway"
)

// CNF defines the RFC 9449 confirmation claim for DPoP binding.
type CNF struct {
	JKT string `json:"jkt"` // RFC 7638 JWK Thumbprint
}

// TokenHeader defines the JWS header for Conjoiner tokens.
type TokenHeader struct {
	Typ string `json:"typ"` // "conjoiner+jwt"
	Alg string `json:"alg"` // "EdDSA"
}

// TaskToken represents an ephemeral, cryptographically bound agent token.
type TaskToken struct {
	JTI           string   `json:"jti"`
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	SessionID     string   `json:"sid,omitempty"`
	Audience      string   `json:"aud"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	Scope         []string `json:"scope"`
	CNF           CNF      `json:"cnf"`
	ParentTokenID string   `json:"parent_jti,omitempty"`
	Depth         int      `json:"depth"`
}

// ScopeSet returns the parsed attenuation.ScopeSet for this token.
func (t *TaskToken) ScopeSet() (attenuation.ScopeSet, error) {
	return attenuation.NewScopeSet(t.Scope...)
}

// IsExpired returns true if the token's expiration time is before the given time.
func (t *TaskToken) IsExpired(now time.Time) bool {
	return now.Unix() > t.ExpiresAt
}

// VerifyDPoPBinding returns true if the token's confirmation thumbprint matches the expected thumbprint.
func (t *TaskToken) VerifyDPoPBinding(expectedThumbprint string) bool {
	if t.CNF.JKT == "" || expectedThumbprint == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(t.CNF.JKT), []byte(expectedThumbprint)) == 1
}

// Sign serializes and cryptographically signs the TaskToken with the Broker's private key.
func (t *TaskToken) Sign(brokerPrivKey ed25519.PrivateKey) (string, error) {
	header := TokenHeader{
		Typ: "conjoiner+jwt",
		Alg: "EdDSA",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed marshaling token header: %w", err)
	}

	payloadJSON, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed marshaling token payload: %w", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerEnc + "." + payloadEnc
	sig := ed25519.Sign(brokerPrivKey, []byte(signingInput))
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigEnc, nil
}

// ParseAndVerifyToken parses and validates a compact JWT token using the Broker's public key.
// ParseAndVerifyToken parses and validates a compact JWT token using the Broker's public key
// and validates against the DefaultRevocationStore.
func ParseAndVerifyToken(tokenJWT string, brokerPubKey ed25519.PublicKey, now time.Time) (*TaskToken, error) {
	return ParseAndVerifyTokenWithRevocation(tokenJWT, brokerPubKey, now, DefaultRevocationStore)
}

// ParseAndVerifyTokenWithRevocation parses and validates a compact JWT token with explicit revocation store checks.
func ParseAndVerifyTokenWithRevocation(tokenJWT string, brokerPubKey ed25519.PublicKey, now time.Time, revStore RevocationStore) (*TaskToken, error) {
	parts := strings.Split(tokenJWT, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header base64: %w", ErrMalformedToken, err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload base64: %w", ErrMalformedToken, err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature base64: %w", ErrMalformedToken, err)
	}

	var header TokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: invalid header json: %w", ErrMalformedToken, err)
	}

	if header.Typ != "conjoiner+jwt" {
		return nil, fmt.Errorf("%w: expected typ 'conjoiner+jwt', got '%s'", ErrMalformedToken, header.Typ)
	}
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: expected alg 'EdDSA', got '%s'", ErrMalformedToken, header.Alg)
	}

	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(brokerPubKey, []byte(signingInput), sigBytes) {
		return nil, ErrInvalidTokenSignature
	}

	var token TaskToken
	if err := json.Unmarshal(payloadBytes, &token); err != nil {
		return nil, fmt.Errorf("%w: invalid payload json: %w", ErrMalformedToken, err)
	}

	// Verify revocation status
	if revStore != nil && revStore.IsRevoked(token.JTI, token.SessionID, token.Subject) {
		return nil, ErrTokenRevoked
	}

	// Verify expiration
	if token.IsExpired(now) {
		return nil, fmt.Errorf("%w: expired at %s, current %s", ErrExpiredToken,
			time.Unix(token.ExpiresAt, 0).UTC(), now.UTC())
	}

	// Verify clock skew (not issued in far future)
	issuedAt := time.Unix(token.IssuedAt, 0).UTC()
	if issuedAt.Sub(now) > 5*time.Second {
		return nil, fmt.Errorf("%w: issued at %s is in future relative to %s", ErrTokenNotYetValid, issuedAt, now)
	}

	return &token, nil
}

// GenerateUUIDv4 produces a cryptographically secure RFC 4122 v4 UUID string.
func GenerateUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("crypto rand failed: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ComputeJWKThumbprint calculates the RFC 7638 JWK thumbprint for an Ed25519 public key.
func ComputeJWKThumbprint(pubKey ed25519.PublicKey) string {
	jwk := JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pubKey),
	}
	return jwk.Thumbprint()
}

// MintWorkloadIdentity mints an ephemeral TaskToken with subject spiffe://bonjo.dev/agent/<session_id>,
// DPoP binding to pubKey, unique UUID JTI, strictly enforced 30s TTL (DefaultTTL), and depth 0.
func MintWorkloadIdentity(sessionID string, pubKey ed25519.PublicKey, scopes []string, privKey ed25519.PrivateKey) (*TaskToken, string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, "", errors.New("sessionID cannot be empty")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, "", errors.New("invalid public key size: expected ed25519.PublicKeySize")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, "", errors.New("invalid private key size: expected ed25519.PrivateKeySize")
	}

	jti, err := GenerateUUIDv4()
	if err != nil {
		return nil, "", fmt.Errorf("failed generating UUID JTI: %w", err)
	}

	jkt := ComputeJWKThumbprint(pubKey)
	now := time.Now().UTC()

	tok := &TaskToken{
		JTI:       jti,
		Issuer:    DefaultIssuer,
		Subject:   fmt.Sprintf("spiffe://bonjo.dev/agent/%s", sessionID),
		SessionID: sessionID,
		Audience:  DefaultAudience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(DefaultTTL).Unix(),
		Scope:     scopes,
		CNF: CNF{
			JKT: jkt,
		},
		Depth: 0,
	}

	signedJWT, err := tok.Sign(privKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed signing workload identity token: %w", err)
	}

	return tok, signedJWT, nil
}
