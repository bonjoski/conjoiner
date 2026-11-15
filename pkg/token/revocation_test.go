package token

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryRevocationStore_JTIRevocation(t *testing.T) {
	store := NewMemoryRevocationStore()

	jti := "jti-test-12345"
	sessionID := "ses-abc-999"
	sub := "agent:worker-1"

	if store.IsRevoked(jti, sessionID, sub) {
		t.Fatal("Expected not revoked initially")
	}

	// Revoke JTI
	exp := time.Now().UTC().Add(30 * time.Second)
	if err := store.Revoke(jti, exp); err != nil {
		t.Fatalf("Failed to revoke JTI: %v", err)
	}

	if !store.IsRevoked(jti, sessionID, sub) {
		t.Fatal("Expected JTI to be revoked")
	}
	if !store.IsRevoked(jti, "", "") {
		t.Fatal("Expected JTI to be revoked when querying JTI only")
	}
	if store.IsRevoked("other-jti", sessionID, sub) {
		t.Fatal("Expected other JTI not to be revoked")
	}
}

func TestMemoryRevocationStore_SessionRevocation(t *testing.T) {
	store := NewMemoryRevocationStore()

	sessionID := "session-compromised-42"
	exp := time.Now().UTC().Add(10 * time.Second)

	if err := store.RevokeSession(sessionID, exp); err != nil {
		t.Fatalf("Failed to revoke session: %v", err)
	}

	// Any token in this session must be reported as revoked
	if !store.IsRevoked("jti-1", sessionID, "agent-1") {
		t.Fatal("Expected session token 1 to be revoked")
	}
	if !store.IsRevoked("jti-2", sessionID, "agent-2") {
		t.Fatal("Expected session token 2 to be revoked")
	}
	if store.IsRevoked("jti-1", "other-session", "agent-1") {
		t.Fatal("Expected other session not to be revoked")
	}
}

func TestMemoryRevocationStore_SubjectRevocation(t *testing.T) {
	store := NewMemoryRevocationStore()

	sub := "malicious-agent-x"
	exp := time.Now().UTC().Add(10 * time.Second)

	if err := store.RevokeSubject(sub, exp); err != nil {
		t.Fatalf("Failed to revoke subject: %v", err)
	}

	if !store.IsRevoked("any-jti", "any-session", sub) {
		t.Fatal("Expected subject to be revoked")
	}
	if store.IsRevoked("any-jti", "any-session", "benign-agent") {
		t.Fatal("Expected benign subject not to be revoked")
	}
}

func TestMemoryRevocationStore_TTLExpiration(t *testing.T) {
	store := NewMemoryRevocationStore()

	jti := "short-lived-jti"
	// Revocation expired in past
	pastExp := time.Now().UTC().Add(-1 * time.Second)
	if err := store.Revoke(jti, pastExp); err != nil {
		t.Fatalf("Failed to set past revocation: %v", err)
	}

	if store.IsRevoked(jti, "", "") {
		t.Fatal("Expected expired revocation not to match")
	}
}

func TestMemoryRevocationStore_ConcurrentN8Stress(t *testing.T) {
	store := NewMemoryRevocationStore()
	const workers = 8
	const opsPerWorker = 500

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				jti := fmt.Sprintf("jti-%d-%d", workerID, i)
				sid := fmt.Sprintf("sid-%d-%d", workerID, i)
				sub := fmt.Sprintf("sub-%d", workerID)

				if i%2 == 0 {
					_ = store.Revoke(jti, time.Now().UTC().Add(10*time.Second))
				} else {
					_ = store.RevokeSession(sid, time.Now().UTC().Add(10*time.Second))
				}

				_ = store.IsRevoked(jti, sid, sub)
			}
		}()
	}

	wg.Wait()

	if store.ActiveRevocationsCount() == 0 {
		t.Fatal("Expected non-zero active revocations after concurrent run")
	}
}
