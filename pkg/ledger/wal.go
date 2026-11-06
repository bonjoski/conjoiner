package ledger

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// safeSessionFilename sanitizes sessionID to prevent directory traversal and path injection attacks.
func safeSessionFilename(sessionID string) string {
	var clean strings.Builder
	for _, r := range sessionID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			clean.WriteRune(r)
		} else {
			clean.WriteRune('_')
		}
	}
	res := clean.String()
	if res == "" || res == "_" {
		res = "default"
	}
	return res + ".wal"
}

// sessionWAL manages an append-only WAL partitioned for a single session.
// Concurrency invariant: Writers within the same session synchronize on s.mu,
// while writers across different sessions execute fully in parallel with zero contention.
type sessionWAL struct {
	mu         sync.Mutex
	sessionID  string
	filePath   string
	file       *os.File
	writer     *bufio.Writer
	lastSeq    uint64
	lastHash   string
	inMemory   bool
	syncWrites bool
	receipts   []*SignedIntentReceipt
}

// newSessionWAL constructs or opens a partitioned session WAL.
func newSessionWAL(sessionID, baseDir string, inMemory, syncWrites bool, pubKey ed25519.PublicKey) (*sessionWAL, error) {
	s := &sessionWAL{
		sessionID:  sessionID,
		inMemory:   inMemory,
		syncWrites: syncWrites,
		lastSeq:    0,
		lastHash:   GenesisPrevHash,
		receipts:   make([]*SignedIntentReceipt, 0),
	}

	if inMemory {
		return s, nil
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create ledger directory %s: %w", baseDir, err)
	}

	s.filePath = filepath.Join(baseDir, safeSessionFilename(sessionID))

	// Open or create the WAL file
	file, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open session WAL %s: %w", s.filePath, err)
	}
	s.file = file

	// Recover existing entries if file already exists
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat session WAL %s: %w", s.filePath, err)
	}

	if stat.Size() > 0 {
		existing, err := VerifyWAL(file, pubKey)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed verifying existing session WAL %s: %w", s.filePath, err)
		}
		if len(existing) > 0 {
			last := existing[len(existing)-1]
			s.lastSeq = last.SequenceNumber
			s.lastHash = last.Hash()
			s.receipts = append(s.receipts, existing...)
		}
	}

	// Seek to end of file for subsequent appends
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed seeking end of WAL %s: %w", s.filePath, err)
	}

	s.writer = bufio.NewWriter(file)
	return s, nil
}

// Append creates, signs, and appends a new receipt to the session WAL.
func (s *sessionWAL) Append(intent IntentRecord, privKey ed25519.PrivateKey) (*SignedIntentReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

	// Persist to WAL
	if !s.inMemory && s.writer != nil {
		data, err := json.Marshal(receipt)
		if err != nil {
			return nil, fmt.Errorf("failed marshaling receipt: %w", err)
		}
		if _, err := s.writer.Write(append(data, '\n')); err != nil {
			return nil, fmt.Errorf("failed writing receipt to WAL: %w", err)
		}
		if err := s.writer.Flush(); err != nil {
			return nil, fmt.Errorf("failed flushing WAL writer: %w", err)
		}
		if s.syncWrites && s.file != nil {
			if err := s.file.Sync(); err != nil {
				return nil, fmt.Errorf("failed syncing WAL to disk: %w", err)
			}
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

	var err error
	if s.writer != nil {
		if flushErr := s.writer.Flush(); flushErr != nil && err == nil {
			err = flushErr
		}
	}
	if s.file != nil {
		if closeErr := s.file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		s.file = nil
		s.writer = nil
	}
	return err
}

// VerifyWAL reads a newline-delimited JSON stream of receipts, verifying sequence monotonicity,
// hash-chain continuity, and Ed25519 signature integrity.
func VerifyWAL(reader io.Reader, pubKey ed25519.PublicKey) ([]*SignedIntentReceipt, error) {
	scanner := bufio.NewScanner(reader)
	// Buffer up to 2MB lines for large receipts
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	var receipts []*SignedIntentReceipt
	expectedSeq := uint64(1)
	expectedPrevHash := GenesisPrevHash

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var receipt SignedIntentReceipt
		if err := json.Unmarshal(line, &receipt); err != nil {
			return nil, fmt.Errorf("%w at line %d: %v", ErrCorruptedWAL, lineNum, err)
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
			return nil, fmt.Errorf("%w at line %d (seq %d): %v",
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
