package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAdversarialTamperResistance_CorruptedSignature(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conjoiner-adversarial-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	engine, err := NewEngine(Config{BaseDir: tmpDir})
	if err != nil {
		t.Fatalf("failed creating engine: %v", err)
	}

	ctx := context.Background()
	sessionID := "adv-sig-tamper"

	// Write 2 valid receipts
	_, err = engine.Record(ctx, IntentRecord{
		SessionID: sessionID, ToolName: "git", Action: "status", Verdict: VerdictAllow,
	})
	if err != nil {
		t.Fatalf("failed recording receipt 1: %v", err)
	}
	_, err = engine.Record(ctx, IntentRecord{
		SessionID: sessionID, ToolName: "git", Action: "diff", Verdict: VerdictAllow,
	})
	if err != nil {
		t.Fatalf("failed recording receipt 2: %v", err)
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("failed closing engine: %v", err)
	}

	// Adversary tampers with the WAL file: modifies 1 byte of receipt_sig in line 1
	walPath := filepath.Join(tmpDir, safeSessionFilename(sessionID))
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("failed reading WAL: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in WAL, got %d", len(lines))
	}

	var r1 SignedIntentReceipt
	if err := json.Unmarshal(lines[0], &r1); err != nil {
		t.Fatalf("failed unmarshaling line 0: %v", err)
	}

	// Corrupt signature
	sigRunes := []rune(r1.ReceiptSignature)
	if sigRunes[0] == 'A' {
		sigRunes[0] = 'B'
	} else {
		sigRunes[0] = 'A'
	}
	r1.ReceiptSignature = string(sigRunes)

	tamperedLine, _ := json.Marshal(r1)
	tamperedData := append(tamperedLine, '\n')
	tamperedData = append(tamperedData, lines[1]...)
	tamperedData = append(tamperedData, '\n')

	if err := os.WriteFile(walPath, tamperedData, 0600); err != nil {
		t.Fatalf("failed writing tampered WAL: %v", err)
	}

	// Reopen engine and verify tamper detection
	engine2, err := NewEngine(Config{BaseDir: tmpDir, PrivateKey: engine.privKey})
	if err != nil {
		t.Fatalf("failed creating engine2: %v", err)
	}
	defer engine2.Close()

	_, err = engine2.VerifySession(sessionID)
	if err == nil {
		t.Fatal("expected VerifySession to fail on corrupted signature, but got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestAdversarialTamperResistance_ModifiedPayload(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conjoiner-adversarial-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	engine, _ := NewEngine(Config{BaseDir: tmpDir})
	ctx := context.Background()
	sessionID := "adv-payload-tamper"

	_, _ = engine.RecordRejection(ctx, IntentRecord{
		SessionID:       sessionID,
		ToolName:        "git",
		Action:          "push",
		Verdict:         VerdictDenyScope,
		RejectionReason: "unauthorized",
	})
	engine.Close()

	// Adversary attempts deceptive alignment: flips verdict from DENY_SCOPE to ALLOW in WAL
	walPath := filepath.Join(tmpDir, safeSessionFilename(sessionID))
	data, _ := os.ReadFile(walPath)
	var r SignedIntentReceipt
	_ = json.Unmarshal(bytes.TrimSpace(data), &r)

	// Tamper payload
	r.Verdict = VerdictAllow
	tamperedLine, _ := json.Marshal(r)
	_ = os.WriteFile(walPath, append(tamperedLine, '\n'), 0600)

	engine2, _ := NewEngine(Config{BaseDir: tmpDir, PrivateKey: engine.privKey})
	defer engine2.Close()

	_, err = engine2.VerifySession(sessionID)
	if err == nil {
		t.Fatal("expected VerifySession to fail on modified payload, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestAdversarialTamperResistance_DeletedMiddleEntry(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conjoiner-adversarial-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	engine, _ := NewEngine(Config{BaseDir: tmpDir})
	ctx := context.Background()
	sessionID := "adv-deleted-entry"

	for i := 1; i <= 3; i++ {
		_, err := engine.Record(ctx, IntentRecord{
			SessionID: sessionID,
			ToolName:  "git",
			Action:    "status",
			Verdict:   VerdictAllow,
		})
		if err != nil {
			t.Fatalf("failed recording receipt %d: %v", i, err)
		}
	}
	engine.Close()

	// Adversary deletes entry 2 (leaves entry 1 and entry 3)
	walPath := filepath.Join(tmpDir, safeSessionFilename(sessionID))
	data, _ := os.ReadFile(walPath)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	tamperedData := append(lines[0], '\n')
	tamperedData = append(tamperedData, lines[2]...)
	tamperedData = append(tamperedData, '\n')
	_ = os.WriteFile(walPath, tamperedData, 0600)

	engine2, _ := NewEngine(Config{BaseDir: tmpDir, PrivateKey: engine.privKey})
	defer engine2.Close()

	_, err = engine2.VerifySession(sessionID)
	if err == nil {
		t.Fatal("expected VerifySession to fail on deleted middle entry, got nil")
	}
	if !errors.Is(err, ErrSequenceDiscontinuity) && !errors.Is(err, ErrBrokenHashChain) {
		t.Fatalf("expected ErrSequenceDiscontinuity or ErrBrokenHashChain, got: %v", err)
	}
}

func TestAdversarialTamperResistance_ReorderedEntries(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "conjoiner-adversarial-*")
	defer os.RemoveAll(tmpDir)

	engine, _ := NewEngine(Config{BaseDir: tmpDir})
	ctx := context.Background()
	sessionID := "adv-reorder-entry"

	for i := 1; i <= 3; i++ {
		_, _ = engine.Record(ctx, IntentRecord{
			SessionID: sessionID,
			ToolName:  "git",
			Action:    "log",
			Verdict:   VerdictAllow,
		})
	}
	engine.Close()

	// Adversary swaps line 2 and line 3
	walPath := filepath.Join(tmpDir, safeSessionFilename(sessionID))
	data, _ := os.ReadFile(walPath)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))

	tamperedData := append(lines[0], '\n')
	tamperedData = append(tamperedData, lines[2]...)
	tamperedData = append(tamperedData, '\n')
	tamperedData = append(tamperedData, lines[1]...)
	tamperedData = append(tamperedData, '\n')
	_ = os.WriteFile(walPath, tamperedData, 0600)

	engine2, _ := NewEngine(Config{BaseDir: tmpDir, PrivateKey: engine.privKey})
	defer engine2.Close()

	_, err := engine2.VerifySession(sessionID)
	if err == nil {
		t.Fatal("expected VerifySession to fail on reordered entries, got nil")
	}
	if !errors.Is(err, ErrSequenceDiscontinuity) && !errors.Is(err, ErrBrokenHashChain) {
		t.Fatalf("expected sequence discontinuity or broken hash chain, got: %v", err)
	}
}

func TestAdversarialTamperResistance_CrossSessionInjection(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "conjoiner-adversarial-*")
	defer os.RemoveAll(tmpDir)

	engine, _ := NewEngine(Config{BaseDir: tmpDir})
	ctx := context.Background()

	// Create valid receipt in session A
	rA, _ := engine.Record(ctx, IntentRecord{
		SessionID: "session-A",
		ToolName:  "git",
		Action:    "status",
		Verdict:   VerdictAllow,
	})

	// Create valid receipt in session B
	_, _ = engine.Record(ctx, IntentRecord{
		SessionID: "session-B",
		ToolName:  "git",
		Action:    "status",
		Verdict:   VerdictAllow,
	})
	engine.Close()

	// Adversary injects rA (with seq altered to 2) into session B
	walPathB := filepath.Join(tmpDir, safeSessionFilename("session-B"))
	rA.SequenceNumber = 2
	lineA, _ := json.Marshal(rA)

	f, _ := os.OpenFile(walPathB, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write(append(lineA, '\n'))
	f.Close()

	engine2, _ := NewEngine(Config{BaseDir: tmpDir, PrivateKey: engine.privKey})
	defer engine2.Close()

	_, err := engine2.VerifySession("session-B")
	if err == nil {
		t.Fatal("expected VerifySession to fail on cross-session injected entry, got nil")
	}
}

func TestAdversarialConcurrency_N8_ParallelSubagents(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conjoiner-concurrency-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	engine, err := NewEngine(Config{
		BaseDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("failed creating engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	const numSubagents = 8
	const operationsPerSubagent = 50

	var wg sync.WaitGroup
	errCh := make(chan error, numSubagents*operationsPerSubagent)

	// Simulate N=8 parallel autonomous subagents in distinct worktrees/sessions
	for a := 1; a <= numSubagents; a++ {
		wg.Add(1)
		go func(agentIdx int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("subagent-worktree-%02d", agentIdx)

			for op := 1; op <= operationsPerSubagent; op++ {
				if op%5 == 0 {
					// Rejection proof every 5th op
					_, err := engine.RecordRejection(ctx, IntentRecord{
						SessionID:       sessionID,
						AgentIdentity:   fmt.Sprintf("agent-%d", agentIdx),
						ToolName:        "git",
						Action:          "push",
						Verdict:         VerdictDenyScope,
						RejectionReason: "unauthorized push",
					})
					if err != nil {
						errCh <- fmt.Errorf("agent %d op %d rejection failed: %w", agentIdx, op, err)
						return
					}
				} else {
					// Allowed tool execution
					_, err := engine.Record(ctx, IntentRecord{
						SessionID:     sessionID,
						AgentIdentity: fmt.Sprintf("agent-%d", agentIdx),
						ToolName:      "git",
						Action:        "status",
						Arguments:     []string{"-s"},
						Verdict:       VerdictAllow,
					})
					if err != nil {
						errCh <- fmt.Errorf("agent %d op %d record failed: %w", agentIdx, op, err)
						return
					}
				}
			}
		}(a)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency error: %v", err)
	}

	// Verify all N=8 sessions independently on disk
	for a := 1; a <= numSubagents; a++ {
		sessionID := fmt.Sprintf("subagent-worktree-%02d", a)
		receipts, err := engine.VerifySession(sessionID)
		if err != nil {
			t.Fatalf("session %s failed verification: %v", sessionID, err)
		}
		if len(receipts) != operationsPerSubagent {
			t.Fatalf("session %s: expected %d receipts, got %d", sessionID, operationsPerSubagent, len(receipts))
		}
	}
}

func TestAdversarialConcurrency_SameSessionContention(t *testing.T) {
	engine, err := NewEngine(Config{InMemory: true})
	if err != nil {
		t.Fatalf("failed creating engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	sessionID := "shared-session-stress"
	const numWriters = 10
	const writesPerWriter = 20

	var wg sync.WaitGroup
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < writesPerWriter; i++ {
				_, err := engine.Record(ctx, IntentRecord{
					SessionID:     sessionID,
					AgentIdentity: fmt.Sprintf("writer-%d", writerID),
					ToolName:      "echo",
					Action:        "print",
					Arguments:     []string{fmt.Sprintf("w%d-i%d", writerID, i)},
					Verdict:       VerdictAllow,
				})
				if err != nil {
					t.Errorf("writer %d failed: %v", writerID, err)
					return
				}
			}
		}(w)
	}

	wg.Wait()

	receipts, err := engine.VerifySession(sessionID)
	if err != nil {
		t.Fatalf("shared session verification failed: %v", err)
	}
	totalExpected := numWriters * writesPerWriter
	if len(receipts) != totalExpected {
		t.Fatalf("expected %d receipts, got %d", totalExpected, len(receipts))
	}
}

func TestAdversarial_PathTraversalSessionID(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "conjoiner-adversarial-*")
	defer os.RemoveAll(tmpDir)

	engine, _ := NewEngine(Config{BaseDir: tmpDir})
	defer engine.Close()

	ctx := context.Background()

	// Attempt path traversal attacks through SessionID
	traversalPayloads := []string{
		"../../../../etc/passwd",
		"../../../../var/log/syslog",
		"/tmp/evil.wal",
		"sub/folder/session",
		"session;rm -rf /",
	}

	for _, payload := range traversalPayloads {
		_, err := engine.Record(ctx, IntentRecord{
			SessionID: payload,
			ToolName:  "git",
			Action:    "status",
			Verdict:   VerdictAllow,
		})
		if err != nil {
			t.Fatalf("recording with payload '%s' failed: %v", payload, err)
		}

		// Ensure no files escaped outside tmpDir
		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			t.Fatalf("failed reading tmpDir: %v", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				t.Fatalf("found unexpected subdirectory in ledger dir: %s", e.Name())
			}
		}
	}
}
