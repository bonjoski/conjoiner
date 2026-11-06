package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"
)

func TestReceiptSigningAndVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}

	r := &SignedIntentReceipt{
		ReceiptID:        GenerateUUID(),
		SequenceNumber:   1,
		PrevReceiptHash:  GenesisPrevHash,
		Timestamp:        time.Now().UTC(),
		SessionID:        "session-test-01",
		AgentIdentity:    "agent-claude",
		ToolName:         "git",
		ArgumentDigest:   ComputeArgumentDigest("git", "status", "", []string{"-s"}),
		MandateSignature: "mandate-sig-123",
		DPoPSignature:    "dpop-sig-456",
		Verdict:          VerdictAllow,
	}

	if err := r.Sign(priv); err != nil {
		t.Fatalf("failed signing receipt: %v", err)
	}

	if r.ReceiptSignature == "" {
		t.Fatal("expected non-empty receipt signature")
	}

	if err := r.Verify(pub); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}

	// Verify tampering invalidates signature
	r.ToolName = "rm"
	if err := r.Verify(pub); err == nil {
		t.Fatal("expected tampered receipt to fail verification, got nil")
	}
}

func TestCryptographicRejectionProof(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}

	r := &SignedIntentReceipt{
		ReceiptID:        GenerateUUID(),
		SequenceNumber:   1,
		PrevReceiptHash:  GenesisPrevHash,
		Timestamp:        time.Now().UTC(),
		SessionID:        "session-rej-01",
		AgentIdentity:    "agent-unauthorized",
		ToolName:         "git",
		ArgumentDigest:   ComputeArgumentDigest("git", "push", "", []string{"--force"}),
		MandateSignature: "mandate-sig-123",
		DPoPSignature:    "dpop-sig-456",
		Verdict:          VerdictDenyScope,
		RejectionReason:  "token scope does not authorize git:push",
	}
	if err := r.Sign(priv); err != nil {
		t.Fatalf("failed signing receipt: %v", err)
	}

	crp := &CryptographicRejectionProof{
		Receipt:   r,
		Verdict:   VerdictDenyScope,
		Reason:    "token scope does not authorize git:push",
		BlockedAt: time.Now().UTC(),
	}
	if err := crp.Sign(priv); err != nil {
		t.Fatalf("failed signing CRP: %v", err)
	}

	if err := crp.Verify(pub); err != nil {
		t.Fatalf("failed verifying CRP: %v", err)
	}

	// Test Error() format
	errMsg := crp.Error()
	if errMsg == "" {
		t.Fatal("expected non-empty error message from CRP")
	}

	// Test RejectionError wrapping and Unwrap
	baseErr := errors.New("insufficient scope")
	rejErr := &RejectionError{
		Proof: crp,
		Err:   baseErr,
	}

	if !errors.Is(rejErr, baseErr) {
		t.Fatal("expected errors.Is(rejErr, baseErr) to be true")
	}

	extracted := ExtractRejectionProof(rejErr)
	if extracted != crp {
		t.Fatalf("expected extracted CRP to match original")
	}
}

func TestLedgerEngineSequentialAndHashChaining(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conjoiner-ledger-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	engine, err := NewEngine(Config{
		BaseDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("failed initializing engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	sessionID := "session-chain-01"

	// 1. Record an ALLOW intent
	r1, err := engine.Record(ctx, IntentRecord{
		SessionID:     sessionID,
		AgentIdentity: "agent-1",
		ToolName:      "git",
		Action:        "status",
		Arguments:     []string{"-s"},
		Verdict:       VerdictAllow,
	})
	if err != nil {
		t.Fatalf("failed recording r1: %v", err)
	}
	if r1.SequenceNumber != 1 {
		t.Fatalf("expected seq 1, got %d", r1.SequenceNumber)
	}
	if r1.PrevReceiptHash != GenesisPrevHash {
		t.Fatalf("expected genesis prev hash, got %s", r1.PrevReceiptHash)
	}

	// 2. Record a DENY_SCOPE intent
	crp2, err := engine.RecordRejection(ctx, IntentRecord{
		SessionID:       sessionID,
		AgentIdentity:   "agent-1",
		ToolName:        "git",
		Action:          "push",
		Verdict:         VerdictDenyScope,
		RejectionReason: "unauthorized action",
	})
	if err != nil {
		t.Fatalf("failed recording crp2: %v", err)
	}
	r2 := crp2.Receipt
	if r2.SequenceNumber != 2 {
		t.Fatalf("expected seq 2, got %d", r2.SequenceNumber)
	}
	if r2.PrevReceiptHash != r1.Hash() {
		t.Fatalf("expected r2.PrevReceiptHash == r1.Hash(), got %s vs %s", r2.PrevReceiptHash, r1.Hash())
	}

	// 3. Record a DENY_DRIFT intent
	crp3, err := engine.RecordRejection(ctx, IntentRecord{
		SessionID:       sessionID,
		AgentIdentity:   "agent-1",
		ToolName:        "git",
		Action:          "status",
		Arguments:       []string{";", "rm", "-rf"},
		Verdict:         VerdictDenyDrift,
		RejectionReason: "command injection detected",
	})
	if err != nil {
		t.Fatalf("failed recording crp3: %v", err)
	}
	r3 := crp3.Receipt
	if r3.SequenceNumber != 3 {
		t.Fatalf("expected seq 3, got %d", r3.SequenceNumber)
	}
	if r3.PrevReceiptHash != r2.Hash() {
		t.Fatalf("expected r3.PrevReceiptHash == r2.Hash(), got %s vs %s", r3.PrevReceiptHash, r2.Hash())
	}

	// 4. Verify entire session on disk
	verified, err := engine.VerifySession(sessionID)
	if err != nil {
		t.Fatalf("session verification failed: %v", err)
	}
	if len(verified) != 3 {
		t.Fatalf("expected 3 verified receipts, got %d", len(verified))
	}
}

func TestLedgerEnginePersistenceAndRecovery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conjoiner-persist-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sessionID := "session-persist-01"

	// Stage 1: write 2 receipts and close engine
	{
		engine, err := NewEngine(Config{
			BaseDir:    tmpDir,
			PrivateKey: priv,
			SyncWrites: true,
		})
		if err != nil {
			t.Fatalf("failed creating initial engine: %v", err)
		}

		ctx := context.Background()
		_, err = engine.Record(ctx, IntentRecord{
			SessionID:     sessionID,
			AgentIdentity: "agent-1",
			ToolName:      "echo",
			Action:        "print",
			Arguments:     []string{"first"},
			Verdict:       VerdictAllow,
		})
		if err != nil {
			t.Fatalf("failed recording first receipt: %v", err)
		}

		_, err = engine.Record(ctx, IntentRecord{
			SessionID:     sessionID,
			AgentIdentity: "agent-1",
			ToolName:      "echo",
			Action:        "print",
			Arguments:     []string{"second"},
			Verdict:       VerdictAllow,
		})
		if err != nil {
			t.Fatalf("failed recording second receipt: %v", err)
		}

		if err := engine.Close(); err != nil {
			t.Fatalf("failed closing engine: %v", err)
		}
	}

	// Stage 2: re-open engine and verify state recovered
	{
		engine2, err := NewEngine(Config{
			BaseDir:    tmpDir,
			PrivateKey: priv,
			SyncWrites: true,
		})
		if err != nil {
			t.Fatalf("failed creating second engine: %v", err)
		}
		defer engine2.Close()

		ctx := context.Background()

		// Append third receipt
		r3, err := engine2.Record(ctx, IntentRecord{
			SessionID:     sessionID,
			AgentIdentity: "agent-1",
			ToolName:      "echo",
			Action:        "print",
			Arguments:     []string{"third"},
			Verdict:       VerdictAllow,
		})
		if err != nil {
			t.Fatalf("failed recording third receipt: %v", err)
		}

		if r3.SequenceNumber != 3 {
			t.Fatalf("expected sequence 3 after recovery, got %d", r3.SequenceNumber)
		}

		// Verify complete WAL from disk
		receipts, err := engine2.VerifySession(sessionID)
		if err != nil {
			t.Fatalf("recovered session verification failed: %v", err)
		}
		if len(receipts) != 3 {
			t.Fatalf("expected 3 receipts in recovered WAL, got %d", len(receipts))
		}
		for _, r := range receipts {
			if err := r.Verify(pub); err != nil {
				t.Fatalf("recovered receipt %d failed verification: %v", r.SequenceNumber, err)
			}
		}
	}
}

func TestInMemoryLedgerEngine(t *testing.T) {
	engine, err := NewEngine(Config{
		InMemory: true,
	})
	if err != nil {
		t.Fatalf("failed creating in-memory engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	sessionID := "mem-session-01"

	r1, err := engine.Record(ctx, IntentRecord{
		SessionID:     sessionID,
		AgentIdentity: "agent-mem",
		ToolName:      "cat",
		Action:        "read",
		Resource:      "test.txt",
		Verdict:       VerdictAllow,
	})
	if err != nil {
		t.Fatalf("failed recording in memory: %v", err)
	}

	if r1.SequenceNumber != 1 {
		t.Fatalf("expected seq 1, got %d", r1.SequenceNumber)
	}

	receipts, err := engine.VerifySession(sessionID)
	if err != nil {
		t.Fatalf("failed verifying in-memory session: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
}
