package token

import (
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	// ErrInvalidRevocationTarget indicates empty identifier when attempting revocation.
	ErrInvalidRevocationTarget = errors.New("revocation identifier cannot be empty")
)

// RevocationStore defines an interface for managing and querying revoked tokens and sessions.
type RevocationStore interface {
	Revoke(jti string, expiresAt time.Time) error
	RevokeSession(sessionID string, expiresAt time.Time) error
	RevokeSubject(subject string, expiresAt time.Time) error
	IsRevoked(jti string, sessionID string, subject string) bool
	ActiveRevocationsCount() int
}

type revocationShard struct {
	mu      sync.RWMutex
	entries map[string]time.Time
}

// MemoryRevocationStore provides a 16-way sharded, thread-safe in-memory RevocationStore.
type MemoryRevocationStore struct {
	shards [numReplayShards]revocationShard
}

// NewMemoryRevocationStore initializes a sharded in-memory revocation store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	s := &MemoryRevocationStore{}
	for i := range s.shards {
		s.shards[i] = revocationShard{
			entries: make(map[string]time.Time),
		}
	}
	return s
}

func (s *MemoryRevocationStore) getShard(key string) *revocationShard {
	return &s.shards[fnv32aShard(key)]
}

// Revoke records a specific JTI as revoked until expiresAt.
func (s *MemoryRevocationStore) Revoke(jti string, expiresAt time.Time) error {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return ErrInvalidRevocationTarget
	}
	return s.setEntry("jti:"+jti, expiresAt)
}

// RevokeSession records all tokens within sessionID as revoked until expiresAt.
func (s *MemoryRevocationStore) RevokeSession(sessionID string, expiresAt time.Time) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ErrInvalidRevocationTarget
	}
	return s.setEntry("sid:"+sessionID, expiresAt)
}

// RevokeSubject records all tokens issued to a subject as revoked until expiresAt.
func (s *MemoryRevocationStore) RevokeSubject(subject string, expiresAt time.Time) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ErrInvalidRevocationTarget
	}
	return s.setEntry("sub:"+subject, expiresAt)
}

func (s *MemoryRevocationStore) setEntry(key string, expiresAt time.Time) error {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.entries[key] = expiresAt

	// Incremental O(1) bounded expiry eviction
	now := time.Now().UTC()
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

	return nil
}

// IsRevoked checks if the given JTI, SessionID, or Subject has been revoked.
// Returns true if ANY of the three match an active revocation entry.
func (s *MemoryRevocationStore) IsRevoked(jti string, sessionID string, subject string) bool {
	now := time.Now().UTC()

	checkKey := func(key string) bool {
		if key == "" {
			return false
		}
		shard := s.getShard(key)
		shard.mu.RLock()
		defer shard.mu.RUnlock()

		if exp, exists := shard.entries[key]; exists {
			if now.Before(exp) {
				return true
			}
		}
		return false
	}

	if jti != "" && checkKey("jti:"+strings.TrimSpace(jti)) {
		return true
	}
	if sessionID != "" && checkKey("sid:"+strings.TrimSpace(sessionID)) {
		return true
	}
	if subject != "" && checkKey("sub:"+strings.TrimSpace(subject)) {
		return true
	}

	return false
}

// ActiveRevocationsCount returns the count of active, non-expired revocations.
func (s *MemoryRevocationStore) ActiveRevocationsCount() int {
	now := time.Now().UTC()
	total := 0
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.RLock()
		for _, exp := range shard.entries {
			if now.Before(exp) {
				total++
			}
		}
		shard.mu.RUnlock()
	}
	return total
}
