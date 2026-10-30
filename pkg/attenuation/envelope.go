package attenuation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrExpiredEnvelope indicates a delegation envelope has passed its expiration time.
	ErrExpiredEnvelope = errors.New("delegation envelope is expired")
	// ErrInvalidEnvelopeSignature indicates signature verification failed.
	ErrInvalidEnvelopeSignature = errors.New("invalid envelope signature")
	// ErrBrokenDelegationChain indicates broken linkage between delegation hops.
	ErrBrokenDelegationChain = errors.New("broken delegation chain")
	// ErrMaxDepthExceeded indicates the delegation chain exceeded maximum allowed depth.
	ErrMaxDepthExceeded = errors.New("delegation chain exceeds maximum permitted depth")
)

const (
	// MaxDelegationDepth defines the maximum hops allowed in a sub-agent hierarchy.
	MaxDelegationDepth = 8
)

// DelegationPayload represents the canonical payload signed at each delegation hop.
type DelegationPayload struct {
	ParentTokenID  string   `json:"parent_token_id"`
	ChildPublicKey string   `json:"child_public_key"` // base64-encoded Ed25519 public key
	Scopes         []string `json:"scopes"`
	IssuedAt       int64    `json:"iat"` // Unix epoch seconds
	ExpiresAt      int64    `json:"exp"` // Unix epoch seconds
	Depth          int      `json:"depth"`
}

// DelegationEnvelope contains the signed payload and cryptographic proof.
type DelegationEnvelope struct {
	Payload   DelegationPayload `json:"payload"`
	Signature string            `json:"signature"` // base64-encoded Ed25519 signature
}

// CanonicalDigest computes the SHA-256 digest of the canonical JSON representation of the payload.
func (p DelegationPayload) CanonicalDigest() ([]byte, error) {
	bytes, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal delegation payload: %w", err)
	}
	digest := sha256.Sum256(bytes)
	return digest[:], nil
}

// CreateEnvelope creates and signs a new DelegationEnvelope from parent to child.
func CreateEnvelope(
	parentTokenID string,
	childPubKey ed25519.PublicKey,
	parentPrivKey ed25519.PrivateKey,
	parentScope ScopeSet,
	requestedScope ScopeSet,
	ttl time.Duration,
	depth int,
) (*DelegationEnvelope, error) {
	if depth > MaxDelegationDepth {
		return nil, fmt.Errorf("%w: depth %d > %d", ErrMaxDepthExceeded, depth, MaxDelegationDepth)
	}

	// Enforce scope attenuation invariant: ChildScope ⊆ ParentScope
	attenuated, err := Attenuate(parentScope, requestedScope)
	if err != nil {
		return nil, fmt.Errorf("scope attenuation failed: %w", err)
	}

	now := time.Now().UTC()
	payload := DelegationPayload{
		ParentTokenID:  parentTokenID,
		ChildPublicKey: base64.StdEncoding.EncodeToString(childPubKey),
		Scopes:         attenuated.Strings(),
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(ttl).Unix(),
		Depth:          depth,
	}

	digest, err := payload.CanonicalDigest()
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(parentPrivKey, digest)

	return &DelegationEnvelope{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify verifies the envelope's cryptographic signature against the parent public key and checks expiry.
func (e *DelegationEnvelope) Verify(parentPubKey ed25519.PublicKey, now time.Time) error {
	if now.Unix() > e.Payload.ExpiresAt {
		return fmt.Errorf("%w: expired at %s, current %s", ErrExpiredEnvelope,
			time.Unix(e.Payload.ExpiresAt, 0).UTC(), now.UTC())
	}

	sigBytes, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("invalid base64 envelope signature: %w", err)
	}

	digest, err := e.Payload.CanonicalDigest()
	if err != nil {
		return err
	}

	if !ed25519.Verify(parentPubKey, digest, sigBytes) {
		return ErrInvalidEnvelopeSignature
	}

	return nil
}

// VerifyChain verifies an entire chain of delegation envelopes from root to leaf.
// Enforces:
// 1. Monotonic scope decay: Scope_i ⊆ Scope_{i-1}
// 2. Signer linkage: Signer of hop i is Child of hop {i-1}
// 3. Cryptographic integrity of each envelope
func VerifyChain(chain []DelegationEnvelope, rootPubKey ed25519.PublicKey, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("delegation chain cannot be empty")
	}
	if len(chain) > MaxDelegationDepth {
		return fmt.Errorf("%w: length %d > %d", ErrMaxDepthExceeded, len(chain), MaxDelegationDepth)
	}

	currentSignerPubKey := rootPubKey
	var currentScopeSet ScopeSet

	for i, env := range chain {
		if env.Payload.Depth != i+1 {
			return fmt.Errorf("%w: expected depth %d at hop %d, got %d",
				ErrBrokenDelegationChain, i+1, i, env.Payload.Depth)
		}

		if err := env.Verify(currentSignerPubKey, now); err != nil {
			return fmt.Errorf("envelope verification failed at hop %d: %w", i, err)
		}

		childScopeSet, err := NewScopeSet(env.Payload.Scopes...)
		if err != nil {
			return fmt.Errorf("invalid scopes at hop %d: %w", i, err)
		}

		// Enforce monotonic decay
		if i > 0 {
			if !IsSubset(childScopeSet, currentScopeSet) {
				return fmt.Errorf("%w at hop %d: child scope is not a subset of parent scope",
					ErrSupersetScopeDenied, i)
			}
		}

		currentScopeSet = childScopeSet

		// Next signer is this hop's child
		childPubKeyBytes, err := base64.StdEncoding.DecodeString(env.Payload.ChildPublicKey)
		if err != nil {
			return fmt.Errorf("invalid child public key at hop %d: %w", i, err)
		}
		if len(childPubKeyBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid child public key size at hop %d: %d", i, len(childPubKeyBytes))
		}
		currentSignerPubKey = ed25519.PublicKey(childPubKeyBytes)
	}

	return nil
}
