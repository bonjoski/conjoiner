package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IntentRecord specifies the parameters for recording a evaluated agent action.
type IntentRecord struct {
	SessionID        string
	AgentIdentity    string
	ToolName         string
	Action           string
	Resource         string
	Arguments        []string
	ArgumentDigest   string
	MandateSignature string
	DPoPSignature    string
	Verdict          PolicyVerdict
	RejectionReason  string
}

// Ledger defines the interface for recording and auditing cryptographically sealed intent receipts.
type Ledger interface {
	Record(ctx context.Context, intent IntentRecord) (*SignedIntentReceipt, error)
	RecordRejection(ctx context.Context, intent IntentRecord) (*CryptographicRejectionProof, error)
	VerifySession(sessionID string) ([]*SignedIntentReceipt, error)
	GetReceipts(sessionID string) ([]*SignedIntentReceipt, error)
	Close() error
	PublicKey() ed25519.PublicKey
}

// Config configures the cryptographic intent ledger engine.
type Config struct {
	BaseDir    string
	InMemory   bool
	PrivateKey ed25519.PrivateKey
	SyncWrites bool
}

// Engine implements Ledger with per-session partitioned WAL files to eliminate lock contention.
type Engine struct {
	mu         sync.RWMutex
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey
	baseDir    string
	inMemory   bool
	syncWrites bool
	sessions   map[string]*sessionWAL
	closed     bool
}

// NewEngine creates and initializes a new Ledger Engine.
func NewEngine(cfg Config) (*Engine, error) {
	priv := cfg.PrivateKey
	var pub ed25519.PublicKey

	if priv == nil {
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed generating ephemeral ledger key: %w", err)
		}
		priv = s
		pub = p
	} else {
		if len(priv) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid private key size: expected ed25519.PrivateKey")
		}
		pub = priv.Public().(ed25519.PublicKey)
	}

	baseDir := cfg.BaseDir
	if baseDir == "" && !cfg.InMemory {
		baseDir = ".conjoiner/sessions"
	}

	return &Engine{
		privKey:    priv,
		pubKey:     pub,
		baseDir:    baseDir,
		inMemory:   cfg.InMemory,
		syncWrites: cfg.SyncWrites,
		sessions:   make(map[string]*sessionWAL),
	}, nil
}

// PublicKey returns the Ed25519 public key used to verify receipts.
func (e *Engine) PublicKey() ed25519.PublicKey {
	return e.pubKey
}

// getOrCreateSession retrieves or instantiates the per-session WAL.
func (e *Engine) getOrCreateSession(sessionID string) (*sessionWAL, error) {
	if sessionID == "" {
		sessionID = "default"
	}

	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return nil, errors.New("ledger engine is closed")
	}
	s, exists := e.sessions[sessionID]
	e.mu.RUnlock()

	if exists {
		return s, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil, errors.New("ledger engine is closed")
	}

	// Double-check under write lock
	if s, exists := e.sessions[sessionID]; exists {
		return s, nil
	}

	newWAL, err := newSessionWAL(sessionID, e.baseDir, e.inMemory, e.syncWrites, e.pubKey)
	if err != nil {
		return nil, err
	}

	e.sessions[sessionID] = newWAL
	return newWAL, nil
}

// Record signs and appends an intent receipt into the session-partitioned WAL.
func (e *Engine) Record(ctx context.Context, intent IntentRecord) (*SignedIntentReceipt, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	wal, err := e.getOrCreateSession(intent.SessionID)
	if err != nil {
		return nil, err
	}

	return wal.Append(intent, e.privKey)
}

// RecordRejection records a policy denial and generates an indisputable CryptographicRejectionProof (CRP).
func (e *Engine) RecordRejection(ctx context.Context, intent IntentRecord) (*CryptographicRejectionProof, error) {
	if intent.Verdict != VerdictDenyScope && intent.Verdict != VerdictDenyDrift {
		intent.Verdict = VerdictDenyDrift
	}

	receipt, err := e.Record(ctx, intent)
	if err != nil {
		return nil, fmt.Errorf("failed recording rejection receipt in WAL: %w", err)
	}

	proof := &CryptographicRejectionProof{
		Receipt:   receipt,
		Verdict:   intent.Verdict,
		Reason:    intent.RejectionReason,
		BlockedAt: time.Now().UTC(),
	}

	if err := proof.Sign(e.privKey); err != nil {
		return nil, fmt.Errorf("failed signing rejection proof: %w", err)
	}

	return proof, nil
}

// VerifySession verifies the entire hash-chained log for the specified session.
func (e *Engine) VerifySession(sessionID string) ([]*SignedIntentReceipt, error) {
	if sessionID == "" {
		sessionID = "default"
	}

	if e.inMemory {
		e.mu.RLock()
		s, exists := e.sessions[sessionID]
		e.mu.RUnlock()
		if !exists {
			return nil, nil
		}
		receipts := s.GetReceipts()
		expectedSeq := uint64(1)
		expectedPrevHash := GenesisPrevHash
		for _, r := range receipts {
			if r.SequenceNumber != expectedSeq {
				return nil, fmt.Errorf("%w: expected seq %d, got %d", ErrSequenceDiscontinuity, expectedSeq, r.SequenceNumber)
			}
			if r.PrevReceiptHash != expectedPrevHash {
				return nil, fmt.Errorf("%w: expected prev_hash %s, got %s", ErrBrokenHashChain, expectedPrevHash, r.PrevReceiptHash)
			}
			if err := r.Verify(e.pubKey); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
			}
			expectedPrevHash = r.Hash()
			expectedSeq++
		}
		return receipts, nil
	}

	filePath := filepath.Join(e.baseDir, safeSessionFilename(sessionID))
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed opening session WAL %s: %w", filePath, err)
	}
	defer file.Close()

	return VerifyWAL(file, e.pubKey)
}

// GetReceipts returns all in-memory receipts recorded for the given session.
func (e *Engine) GetReceipts(sessionID string) ([]*SignedIntentReceipt, error) {
	if sessionID == "" {
		sessionID = "default"
	}

	e.mu.RLock()
	s, exists := e.sessions[sessionID]
	e.mu.RUnlock()

	if !exists {
		// If on disk, try reading it
		if !e.inMemory {
			return e.VerifySession(sessionID)
		}
		return nil, nil
	}

	return s.GetReceipts(), nil
}

// Close gracefully flushes and closes all open session WAL files.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}
	e.closed = true

	var firstErr error
	for _, s := range e.sessions {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
