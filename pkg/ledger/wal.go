package ledger

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SanitizeSessionID restricts session identifiers to safe filename characters [a-zA-Z0-9_-].
// If unsafe characters or excessive length are present, a collision-resistant hash suffix is appended.
func SanitizeSessionID(sessionID string) string {
	trimmed := strings.TrimSpace(sessionID)
	if trimmed == "" {
		return "default"
	}

	var clean strings.Builder
	hadUnsafe := false
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			if clean.Len() < 64 {
				clean.WriteRune(r)
			}
		} else {
			hadUnsafe = true
			if clean.Len() < 64 {
				clean.WriteRune('_')
			}
		}
	}

	res := clean.String()
	if res == "" || res == "_" {
		res = "default"
		hadUnsafe = true
	}

	if hadUnsafe || len(trimmed) > 64 {
		sum := sha256.Sum256([]byte(trimmed))
		res = res + "-" + hex.EncodeToString(sum[:8])
	}
	return res
}

// safeSessionFilename sanitizes sessionID to prevent directory traversal and path injection attacks.
func safeSessionFilename(sessionID string) string {
	return SanitizeSessionID(sessionID) + ".wal"
}

func verifySafeDirectory(dir string) error {
	cleanDir := filepath.Clean(dir)
	if fi, err := os.Lstat(cleanDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked ledger directory: %s", cleanDir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("ledger base path is not a directory: %s", cleanDir)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed stating ledger directory %s: %w", cleanDir, err)
	}

	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return fmt.Errorf("failed to create ledger directory %s: %w", cleanDir, err)
	}
	return nil
}

func openSafeWALFile(filePath string, flags int) (*os.File, error) {
	if fi, err := os.Lstat(filePath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlinked WAL file: %s", filePath)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular WAL file: %s", filePath)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed lstat on WAL file %s: %w", filePath, err)
	}

	f, err := os.OpenFile(filePath, flags|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}

	if fi, statErr := f.Stat(); statErr == nil && fi.Mode().Perm() != 0600 && (flags&(os.O_RDWR|os.O_WRONLY)) != 0 {
		if chmodErr := f.Chmod(0600); chmodErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed enforcing 0600 mode on WAL %s: %w", filePath, chmodErr)
		}
	}
	return f, nil
}

// sessionWAL manages an append-only WAL partitioned for a single session.
// Concurrency invariant: Writers within the same process synchronize on s.mu,
// and cross-process writers synchronize via kernel advisory locks (syscall.Flock).
type sessionWAL struct {
	mu         sync.Mutex
	sessionID  string
	filePath   string
	file       *os.File
	pubKey     ed25519.PublicKey
	lastSeq    uint64
	lastHash   string
	lastOffset int64
	inMemory   bool
	syncWrites bool
	receipts   []*SignedIntentReceipt
}

// newSessionWAL constructs or opens a partitioned session WAL.
func newSessionWAL(sessionID, baseDir string, inMemory, syncWrites bool, pubKey ed25519.PublicKey) (*sessionWAL, error) {
	cleanSessionID := SanitizeSessionID(sessionID)
	s := &sessionWAL{
		sessionID:  cleanSessionID,
		pubKey:     pubKey,
		inMemory:   inMemory,
		syncWrites: syncWrites,
		lastSeq:    0,
		lastHash:   GenesisPrevHash,
		receipts:   make([]*SignedIntentReceipt, 0),
	}

	if inMemory {
		return s, nil
	}

	if err := verifySafeDirectory(baseDir); err != nil {
		return nil, err
	}

	s.filePath = filepath.Join(baseDir, safeSessionFilename(cleanSessionID))

	// CNJ-06: Open WAL with O_CREATE | O_RDWR | O_APPEND | O_NOFOLLOW and strict 0600 permissions
	file, err := openSafeWALFile(s.filePath, os.O_CREATE|os.O_RDWR|os.O_APPEND)
	if err != nil {
		return nil, fmt.Errorf("failed to open session WAL %s: %w", s.filePath, err)
	}
	s.file = file

	// Acquire shared flock while recovering existing hash chain state
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed locking session WAL %s: %w", s.filePath, err)
	}

	err = s.refreshFromDiskLocked()
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if unlockErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed unlocking session WAL %s: %w", s.filePath, unlockErr)
	}

	return s, nil
}

func (s *sessionWAL) refreshFromDiskLocked() error {
	stat, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat session WAL %s: %w", s.filePath, err)
	}

	if stat.Size() == 0 {
		s.lastSeq = 0
		s.lastHash = GenesisPrevHash
		s.lastOffset = 0
		s.receipts = s.receipts[:0]
		return nil
	}

	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed seeking start of WAL %s: %w", s.filePath, err)
	}

	existing, err := VerifyWAL(s.file, s.pubKey)
	if err != nil {
		return fmt.Errorf("failed verifying existing session WAL %s: %w", s.filePath, err)
	}

	s.receipts = existing
	if len(existing) > 0 {
		for _, r := range existing {
			if r.SessionID != s.sessionID {
				return fmt.Errorf("%w: cross-session receipt '%s' found in WAL for '%s'", ErrCorruptedWAL, r.SessionID, s.sessionID)
			}
		}
		last := existing[len(existing)-1]
		s.lastSeq = last.SequenceNumber
		s.lastHash = last.Hash()
	} else {
		s.lastSeq = 0
		s.lastHash = GenesisPrevHash
	}
	s.lastOffset = stat.Size()
	return nil
}

// Append creates, signs, and appends a new receipt to the session WAL under exclusive flock.
func (s *sessionWAL) Append(intent IntentRecord, privKey ed25519.PrivateKey) (*SignedIntentReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.inMemory && s.file != nil {
		if err := syscall.Flock(int(s.file.Fd()), syscall.LOCK_EX); err != nil {
			return nil, fmt.Errorf("failed acquiring exclusive flock on WAL %s: %w", s.filePath, err)
		}
		defer func() {
			_ = syscall.Flock(int(s.file.Fd()), syscall.LOCK_UN)
		}()

		// If another process appended to this session WAL since our last write, sync hash-chain head before signing
		stat, err := s.file.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed stating WAL %s under flock: %w", s.filePath, err)
		}
		if stat.Size() != s.lastOffset {
			if err := s.refreshFromDiskLocked(); err != nil {
				return nil, err
			}
		}
	}

	argDigest := intent.ArgumentDigest
	if argDigest == "" {
		argDigest = ComputeArgumentDigest(intent.ToolName, intent.Action, intent.Resource, intent.Arguments)
	}

	nextSeq := s.lastSeq + 1
	prevHash := s.lastHash

	receipt := &SignedIntentReceipt{
		ReceiptID:        GenerateUUID(),
		SequenceNumber:   nextSeq,
		PrevReceiptHash:  prevHash,
		Timestamp:        time.Now().UTC(),
		SessionID:        s.sessionID,
		AgentIdentity:    intent.AgentIdentity,
		ToolName:         intent.ToolName,
		ArgumentDigest:   argDigest,
		MandateSignature: intent.MandateSignature,
		DPoPSignature:    intent.DPoPSignature,
		Verdict:          intent.Verdict,
		RejectionReason:  intent.RejectionReason,
	}

	if err := receipt.Sign(privKey); err != nil {
		return nil, fmt.Errorf("failed signing receipt: %w", err)
	}

	// Persist atomically via O_APPEND under LOCK_EX
	if !s.inMemory && s.file != nil {
		data, err := json.Marshal(receipt)
		if err != nil {
			return nil, fmt.Errorf("failed marshaling receipt: %w", err)
		}
		line := append(data, '\n')
		if _, err := s.file.Write(line); err != nil {
			return nil, fmt.Errorf("failed writing receipt to WAL: %w", err)
		}
		if s.syncWrites {
			if err := s.file.Sync(); err != nil {
				return nil, fmt.Errorf("failed syncing WAL to disk: %w", err)
			}
		}
		if statAfter, err := s.file.Stat(); err == nil {
			s.lastOffset = statAfter.Size()
		} else {
			s.lastOffset += int64(len(line))
		}
	}

	s.lastSeq = nextSeq
	s.lastHash = receipt.Hash()
	s.receipts = append(s.receipts, receipt)

	return receipt, nil
}

// GetReceipts returns a shallow copy of in-memory receipts for this session.
func (s *sessionWAL) GetReceipts() []*SignedIntentReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*SignedIntentReceipt, len(s.receipts))
	copy(out, s.receipts)
	return out
}

// Close flushes and closes the WAL file if open.
func (s *sessionWAL) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		return err
	}
	return nil
}

// VerifyWAL reads a newline-delimited JSON stream of receipts, verifying sequence monotonicity,
// session consistency, hash-chain continuity, and Ed25519 signature integrity.
func VerifyWAL(reader io.Reader, pubKey ed25519.PublicKey) ([]*SignedIntentReceipt, error) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	var receipts []*SignedIntentReceipt
	expectedSeq := uint64(1)
	expectedPrevHash := GenesisPrevHash
	expectedSession := ""

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var receipt SignedIntentReceipt
		if err := json.Unmarshal(line, &receipt); err != nil {
			return nil, fmt.Errorf("%w at line %d: %w", ErrCorruptedWAL, lineNum, err)
		}

		if expectedSession == "" {
			expectedSession = receipt.SessionID
		} else if receipt.SessionID != expectedSession {
			return nil, fmt.Errorf("%w at line %d: session mismatch ('%s' != '%s')",
				ErrTamperedReceipt, lineNum, receipt.SessionID, expectedSession)
		}

		if receipt.SequenceNumber != expectedSeq {
			return nil, fmt.Errorf("%w at line %d: expected seq %d, got %d",
				ErrSequenceDiscontinuity, lineNum, expectedSeq, receipt.SequenceNumber)
		}

		if receipt.PrevReceiptHash != expectedPrevHash {
			return nil, fmt.Errorf("%w at line %d (seq %d): expected prev_hash %s, got %s",
				ErrBrokenHashChain, lineNum, receipt.SequenceNumber, expectedPrevHash, receipt.PrevReceiptHash)
		}

		if err := receipt.Verify(pubKey); err != nil {
			return nil, fmt.Errorf("%w at line %d (seq %d): %w",
				ErrInvalidSignature, lineNum, receipt.SequenceNumber, err)
		}

		expectedPrevHash = receipt.Hash()
		expectedSeq++
		receipts = append(receipts, &receipt)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return receipts, nil
}
