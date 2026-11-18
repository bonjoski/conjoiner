package token

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// ErrInvalidRevocationTarget indicates empty identifier when attempting revocation.
	ErrInvalidRevocationTarget = errors.New("revocation identifier cannot be empty")
)

// RevocationEntry stores an expiration timestamp and optional forensic reason.
type RevocationEntry struct {
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

// RevocationStore defines an interface for managing and querying revoked tokens and sessions.
type RevocationStore interface {
	Revoke(jti string, expiresAt time.Time) error
	RevokeWithReason(jti string, expiresAt time.Time, reason string) error
	RevokeSession(sessionID string, expiresAt time.Time) error
	RevokeSubject(subject string, expiresAt time.Time) error
	IsRevoked(jti string, sessionID string, subject string) bool
	ActiveRevocationsCount() int
}

// DefaultRevocationStore is the package-level shared in-memory revocation store.
var DefaultRevocationStore RevocationStore = NewMemoryRevocationStore()

type revocationShard struct {
	mu      sync.RWMutex
	entries map[string]RevocationEntry
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
			entries: make(map[string]RevocationEntry),
		}
	}
	return s
}

func (s *MemoryRevocationStore) getShard(key string) *revocationShard {
	return &s.shards[fnv32aShard(key)]
}

// Revoke records a specific JTI as revoked until expiresAt.
func (s *MemoryRevocationStore) Revoke(jti string, expiresAt time.Time) error {
	return s.RevokeWithReason(jti, expiresAt, "")
}

// RevokeWithReason records a specific JTI as revoked until expiresAt with an explanatory reason.
func (s *MemoryRevocationStore) RevokeWithReason(jti string, expiresAt time.Time, reason string) error {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return ErrInvalidRevocationTarget
	}
	return s.setEntry("jti:"+jti, expiresAt, reason)
}

// RevokeSession records all tokens within sessionID as revoked until expiresAt.
func (s *MemoryRevocationStore) RevokeSession(sessionID string, expiresAt time.Time) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ErrInvalidRevocationTarget
	}
	return s.setEntry("sid:"+sessionID, expiresAt, "")
}

// RevokeSubject records all tokens issued to a subject as revoked until expiresAt.
func (s *MemoryRevocationStore) RevokeSubject(subject string, expiresAt time.Time) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ErrInvalidRevocationTarget
	}
	return s.setEntry("sub:"+subject, expiresAt, "")
}

func (s *MemoryRevocationStore) setEntry(key string, expiresAt time.Time, reason string) error {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.entries[key] = RevocationEntry{
		ExpiresAt: expiresAt,
		Reason:    reason,
	}

	// Incremental O(1) bounded expiry eviction
	now := time.Now().UTC()
	sampled := 0
	for k, entry := range shard.entries {
		if !now.Before(entry.ExpiresAt) {
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

		if entry, exists := shard.entries[key]; exists {
			if now.Before(entry.ExpiresAt) {
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
		for _, entry := range shard.entries {
			if now.Before(entry.ExpiresAt) {
				total++
			}
		}
		shard.mu.RUnlock()
	}
	return total
}

// PersistentRevocationRecord represents an on-disk revocation entry.
type PersistentRevocationRecord struct {
	Target    string    `json:"target"` // "jti:...", "sid:...", "sub:..."
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

// LoadRevocationsFromFile loads active revocations from a JSON file into the store.
func LoadRevocationsFromFile(store RevocationStore, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var records []PersistentRevocationRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, rec := range records {
		if now.Before(rec.ExpiresAt) {
			if strings.HasPrefix(rec.Target, "jti:") {
				_ = store.RevokeWithReason(strings.TrimPrefix(rec.Target, "jti:"), rec.ExpiresAt, rec.Reason)
			} else if strings.HasPrefix(rec.Target, "sid:") {
				_ = store.RevokeSession(strings.TrimPrefix(rec.Target, "sid:"), rec.ExpiresAt)
			} else if strings.HasPrefix(rec.Target, "sub:") {
				_ = store.RevokeSubject(strings.TrimPrefix(rec.Target, "sub:"), rec.ExpiresAt)
			}
		}
	}
	return nil
}

// PersistRevocationToFile appends a revocation to a JSON file.
func PersistRevocationToFile(filePath string, target string, expiresAt time.Time, reason string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	var records []PersistentRevocationRecord
	if data, err := os.ReadFile(filePath); err == nil {
		_ = json.Unmarshal(data, &records)
	}

	now := time.Now().UTC()
	active := make([]PersistentRevocationRecord, 0, len(records)+1)
	for _, r := range records {
		if now.Before(r.ExpiresAt) && r.Target != target {
			active = append(active, r)
		}
	}
	active = append(active, PersistentRevocationRecord{
		Target:    target,
		ExpiresAt: expiresAt,
		Reason:    reason,
	})

	out, err := json.MarshalIndent(active, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, out, 0600)
}
