package token

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrReplayDetected indicates the token or proof identifier was previously observed.
	ErrReplayDetected = errors.New("identifier already recorded in replay window")
)

// ReplayCache defines an interface for tracking seen JTIs to prevent replay attacks.
type ReplayCache interface {
	CheckAndSet(jti string, expiresAt time.Time) error
}

// MemoryReplayCache provides an in-memory thread-safe implementation of ReplayCache.
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryReplayCache initializes a new in-memory replay cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{
		entries: make(map[string]time.Time),
	}
}

// CheckAndSet checks if the given jti exists. If found and not expired, returns ErrReplayDetected.
// Otherwise, records the jti with its expiration time.
func (c *MemoryReplayCache) CheckAndSet(jti string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()

	// Clean expired entries on each check or if table grows
	if len(c.entries) > 100 {
		for k, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, k)
			}
		}
	}

	if exp, exists := c.entries[jti]; exists {
		if now.Before(exp) {
			return ErrReplayDetected
		}
	}

	c.entries[jti] = expiresAt
	return nil
}

// PurgeExpired explicitly sweeps all expired entries from cache.
func (c *MemoryReplayCache) PurgeExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}
}

// Len returns the current count of cached JTIs.
func (c *MemoryReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// ContextReplayCacheWrapper provides context propagation if needed.
type ContextReplayCacheWrapper struct {
	cache ReplayCache
}

// NewContextReplayCacheWrapper wraps ReplayCache.
func NewContextReplayCacheWrapper(c ReplayCache) *ContextReplayCacheWrapper {
	return &ContextReplayCacheWrapper{cache: c}
}

// CheckAndSet wraps cache CheckAndSet with context checking.
func (w *ContextReplayCacheWrapper) CheckAndSet(ctx context.Context, jti string, expiresAt time.Time) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return w.cache.CheckAndSet(jti, expiresAt)
	}
}
