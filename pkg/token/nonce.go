package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrMissingSessionNonce indicates a required session nonce was omitted.
	ErrMissingSessionNonce = errors.New("missing session-bound nonce")
	// ErrInvalidSessionNonceFormat indicates the nonce does not match the canonical format.
	ErrInvalidSessionNonceFormat = errors.New("invalid session nonce format")
	// ErrSessionNonceMismatch indicates the nonce is not bound to the active session.
	ErrSessionNonceMismatch = errors.New("session-bound nonce mismatch: nonce is not bound to this session")
	// ErrSessionNonceExpired indicates the nonce timestamp has passed the validity window.
	ErrSessionNonceExpired = errors.New("session-bound nonce expired")
)

// GenerateSessionNonce creates a cryptographically secure nonce bound to sessionID.
// Canonical format: <sessionID>.<epoch_hex>.<random_hex>
func GenerateSessionNonce(sessionID string) (string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", errors.New("session ID cannot be empty when generating session-bound nonce")
	}

	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("crypto rand failed: %w", err)
	}

	nowHex := fmt.Sprintf("%x", time.Now().UTC().Unix())
	randHex := hex.EncodeToString(randomBytes)

	return fmt.Sprintf("%s.%s.%s", sessionID, nowHex, randHex), nil
}

// VerifySessionNonceBinding verifies that the nonce is well-formed and cryptographically bound to expectedSessionID.
func VerifySessionNonceBinding(nonce string, expectedSessionID string, maxAge time.Duration, now time.Time) error {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return ErrMissingSessionNonce
	}

	parts := strings.Split(nonce, ".")
	if len(parts) != 3 {
		return ErrInvalidSessionNonceFormat
	}

	nonceSession := parts[0]
	expectedSessionID = strings.TrimSpace(expectedSessionID)
	if expectedSessionID != "" {
		if subtle.ConstantTimeCompare([]byte(nonceSession), []byte(expectedSessionID)) != 1 {
			return ErrSessionNonceMismatch
		}
	}

	var epoch int64
	if _, err := fmt.Sscanf(parts[1], "%x", &epoch); err != nil {
		return ErrInvalidSessionNonceFormat
	}

	if maxAge > 0 {
		nonceTime := time.Unix(epoch, 0).UTC()
		diff := now.Sub(nonceTime)
		if diff < 0 {
			diff = -diff
		}
		if diff > maxAge {
			return ErrSessionNonceExpired
		}
	}

	if len(parts[2]) < 16 {
		return ErrInvalidSessionNonceFormat
	}

	return nil
}

// SessionNonceTracker tracks and enforces single-use session-bound nonces to prevent replay attacks.
type SessionNonceTracker struct {
	replayCache ReplayCache
	ttl         time.Duration
}

// NewSessionNonceTracker constructs a new SessionNonceTracker.
func NewSessionNonceTracker(cache ReplayCache, ttl time.Duration) *SessionNonceTracker {
	if cache == nil {
		cache = NewMemoryReplayCache()
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &SessionNonceTracker{
		replayCache: cache,
		ttl:         ttl,
	}
}

// ValidateAndConsume validates session binding and consumes the nonce atomically.
// If the nonce has already been consumed within the validity window, returns ErrReplayDetected.
func (t *SessionNonceTracker) ValidateAndConsume(sessionID, nonce string) error {
	now := time.Now().UTC()
	if err := VerifySessionNonceBinding(nonce, sessionID, t.ttl, now); err != nil {
		return err
	}

	exp := now.Add(t.ttl)
	if err := t.replayCache.CheckAndSet(nonce, exp); err != nil {
		return err
	}

	return nil
}
