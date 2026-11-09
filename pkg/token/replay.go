package token

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	numReplayShards           = 16
	defaultMaxEntriesPerShard = 4096
	incrementalEvictionSample = 8
)

var (
	// ErrReplayDetected indicates the token or proof identifier was previously observed.
	ErrReplayDetected = errors.New("identifier already recorded in replay window")
	// ErrReplayCacheFull indicates the shard reached capacity with active unexpired entries.
	ErrReplayCacheFull = errors.New("replay cache shard capacity exhausted")
)

// ReplayCache defines an interface for tracking seen JTIs to prevent replay attacks.
type ReplayCache interface {
	CheckAndSet(jti string, expiresAt time.Time) error
}

type replayShard struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	maxEntries int
}

// MemoryReplayCache provides a 16-way sharded, bounded in-memory thread-safe implementation of ReplayCache.
type MemoryReplayCache struct {
	shards [numReplayShards]replayShard
}

// NewMemoryReplayCache initializes a sharded in-memory replay cache with default bounded per-shard capacity.
func NewMemoryReplayCache() *MemoryReplayCache {
	return NewBoundedMemoryReplayCache(defaultMaxEntriesPerShard)
}

// NewBoundedMemoryReplayCache initializes a 16-shard replay cache with explicit maximum capacity per shard.
func NewBoundedMemoryReplayCache(maxEntriesPerShard int) *MemoryReplayCache {
	if maxEntriesPerShard <= 0 {
		maxEntriesPerShard = defaultMaxEntriesPerShard
	}
	c := &MemoryReplayCache{}
	for i := range c.shards {
		c.shards[i] = replayShard{
			entries:    make(map[string]time.Time),
			maxEntries: maxEntriesPerShard,
		}
	}
	return c
}

func fnv32aShard(key string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h % numReplayShards
}

// CheckAndSet checks if the given jti exists. If found and not expired, returns ErrReplayDetected.
// Performs O(1) incremental expiry sampling per call rather than full-map scans under a global mutex.
func (c *MemoryReplayCache) CheckAndSet(jti string, expiresAt time.Time) error {
	if strings.TrimSpace(jti) == "" {
		return ErrInvalidDPoPProof
	}

	shard := &c.shards[fnv32aShard(jti)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now().UTC()

	if exp, exists := shard.entries[jti]; exists {
		if now.Before(exp) {
			return ErrReplayDetected
		}
		delete(shard.entries, jti)
	}

	// Incremental O(1) bounded expiry eviction (Go randomizes map iteration offsets)
	sampled := 0
	for k, exp := range shard.entries {
		if !now.Before(exp) {
			delete(shard.entries, k)
		}
		sampled++
		if sampled >= incrementalEvictionSample {
			break
		}
	}

	// Enforce bounded shard capacity; sweep expired entries in this shard before failing closed
	if len(shard.entries) >= shard.maxEntries {
		for k, exp := range shard.entries {
			if !now.Before(exp) {
				delete(shard.entries, k)
			}
		}
		if len(shard.entries) >= shard.maxEntries {
			return ErrReplayCacheFull
		}
	}

	shard.entries[jti] = expiresAt
	return nil
}

// PurgeExpired explicitly sweeps all expired entries across all shards.
func (c *MemoryReplayCache) PurgeExpired(now time.Time) {
	for i := range c.shards {
		shard := &c.shards[i]
		shard.mu.Lock()
		for k, exp := range shard.entries {
			if !now.Before(exp) {
				delete(shard.entries, k)
			}
		}
		shard.mu.Unlock()
	}
}

// Len returns the current count of cached JTIs across all shards.
func (c *MemoryReplayCache) Len() int {
	total := 0
	for i := range c.shards {
		shard := &c.shards[i]
		shard.mu.Lock()
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	return total
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
