package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"
)

var (
	// ErrTamperedReceipt indicates data integrity check failed on a receipt.
	ErrTamperedReceipt = errors.New("tampered receipt: data integrity check failed")
	// ErrInvalidSignature indicates cryptographic signature verification failed.
	ErrInvalidSignature = errors.New("invalid cryptographic signature on receipt")
	// ErrMissingSignature indicates signature was empty.
	ErrMissingSignature = errors.New("missing cryptographic signature on receipt")
	// ErrBrokenHashChain indicates previous hash does not match prior receipt hash.
	ErrBrokenHashChain = errors.New("broken hash chain: previous hash does not match prior receipt")
	// ErrSequenceDiscontinuity indicates sequence number is out of order.
	ErrSequenceDiscontinuity = errors.New("sequence discontinuity: sequence number out of order")
	// ErrCorruptedWAL indicates malformed entry in WAL.
	ErrCorruptedWAL = errors.New("corrupted WAL entry")
)

// GenesisPrevHash is the initial prev_hash for sequence 1.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// PolicyVerdict defines the outcome of policy evaluation.
type PolicyVerdict string

const (
	// VerdictAllow indicates the requested tool execution was authorized.
	VerdictAllow PolicyVerdict = "ALLOW"
	// VerdictDenyScope indicates the action was denied due to insufficient token scope.
	VerdictDenyScope PolicyVerdict = "DENY_SCOPE"
	// VerdictDenyDrift indicates the action was denied due to parameter drift, argument injection, or path traversal.
	VerdictDenyDrift PolicyVerdict = "DENY_DRIFT"
)

func writeUint64BE(h hash.Hash, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, _ = h.Write(buf[:])
}

func writeLenPrefixedBytes(h hash.Hash, b []byte) {
	writeUint64BE(h, uint64(len(b)))
	_, _ = h.Write(b)
}

func writeLenPrefixedString(h hash.Hash, s string) {
	writeUint64BE(h, uint64(len(s)))
	_, _ = h.Write([]byte(s))
}

// SignedIntentReceipt (SIR) represents an indisputable, tamper-evident cryptographic receipt
// recorded into an append-only WAL fulfilling NIST SP 800-207A Tenet #7.
type SignedIntentReceipt struct {
	ReceiptID        string        `json:"receipt_id"`
	SequenceNumber   uint64        `json:"seq"`
	PrevReceiptHash  string        `json:"prev_hash"`
	Timestamp        time.Time     `json:"timestamp"`
	SessionID        string        `json:"session_id"`
	AgentIdentity    string        `json:"agent_identity"`
	ToolName         string        `json:"tool_name"`
	ArgumentDigest   string        `json:"arg_digest"`
	MandateSignature string        `json:"mandate_sig"`
	DPoPSignature    string        `json:"dpop_sig"`
	Verdict          PolicyVerdict `json:"verdict"`
	RejectionReason  string        `json:"rejection_reason,omitempty"`
	ReceiptSignature string        `json:"receipt_sig"`
}

// SigningInput computes the unambiguous uint64 big-endian length-prefixed canonical digest of the receipt (CNJ-07).
func (r *SignedIntentReceipt) SigningInput() []byte {
	h := sha256.New()
	writeLenPrefixedString(h, "conjoiner:sir:v2")
	writeLenPrefixedString(h, r.ReceiptID)
	writeUint64BE(h, r.SequenceNumber)
	writeLenPrefixedString(h, r.PrevReceiptHash)
	writeUint64BE(h, uint64(r.Timestamp.UTC().UnixNano()))
	writeLenPrefixedString(h, r.SessionID)
	writeLenPrefixedString(h, r.AgentIdentity)
	writeLenPrefixedString(h, r.ToolName)
	writeLenPrefixedString(h, r.ArgumentDigest)
	writeLenPrefixedString(h, r.MandateSignature)
	writeLenPrefixedString(h, r.DPoPSignature)
	writeLenPrefixedString(h, string(r.Verdict))
	writeLenPrefixedString(h, r.RejectionReason)
	return h.Sum(nil)
}

// Sign signs the receipt with Conjoiner's Ed25519 private key.
func (r *SignedIntentReceipt) Sign(privKey ed25519.PrivateKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return errors.New("invalid private key size: expected ed25519.PrivateKey")
	}
	sig := ed25519.Sign(privKey, r.SigningInput())
	r.ReceiptSignature = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

// Verify verifies the receipt's Ed25519 signature against Conjoiner's public key.
func (r *SignedIntentReceipt) Verify(pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key size: expected ed25519.PublicKey")
	}
	if r.ReceiptSignature == "" {
		return ErrMissingSignature
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(r.ReceiptSignature)
	if err != nil {
		return fmt.Errorf("%w: invalid signature encoding: %w", ErrInvalidSignature, err)
	}
	if !ed25519.Verify(pubKey, r.SigningInput(), sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// Hash computes the cryptographic SHA-256 hash of this receipt including its signature.
// This hash serves as the PrevReceiptHash for the next receipt in the session chain.
func (r *SignedIntentReceipt) Hash() string {
	h := sha256.New()
	writeLenPrefixedString(h, "conjoiner:sir-hash:v2")
	writeLenPrefixedBytes(h, r.SigningInput())
	writeLenPrefixedString(h, r.ReceiptSignature)
	return hex.EncodeToString(h.Sum(nil))
}

// CryptographicRejectionProof (CRP) is emitted when an agent attempts an unauthorized state change,
// out-of-scope mutation, or parameter drift, proving that the action was intercepted and rejected before execution.
type CryptographicRejectionProof struct {
	Receipt        *SignedIntentReceipt `json:"receipt"`
	Verdict        PolicyVerdict        `json:"verdict"`
	Reason         string               `json:"reason"`
	BlockedAt      time.Time            `json:"blocked_at"`
	ProofSignature string               `json:"proof_sig"`
}

// Error implements the error interface for CryptographicRejectionProof.
func (crp *CryptographicRejectionProof) Error() string {
	if crp == nil {
		return "cryptographic rejection proof: nil"
	}
	receiptID := "unknown"
	seq := uint64(0)
	if crp.Receipt != nil {
		receiptID = crp.Receipt.ReceiptID
		seq = crp.Receipt.SequenceNumber
	}
	return fmt.Sprintf("cryptographic rejection proof [%s]: %s (receipt %s, seq %d)",
		crp.Verdict, crp.Reason, receiptID, seq)
}

// SigningInput computes the unambiguous length-prefixed canonical digest of the rejection proof.
func (crp *CryptographicRejectionProof) SigningInput() []byte {
	receiptHash := ""
	if crp.Receipt != nil {
		receiptHash = crp.Receipt.Hash()
	}
	h := sha256.New()
	writeLenPrefixedString(h, "conjoiner:crp:v2")
	writeLenPrefixedString(h, receiptHash)
	writeLenPrefixedString(h, string(crp.Verdict))
	writeLenPrefixedString(h, crp.Reason)
	writeUint64BE(h, uint64(crp.BlockedAt.UTC().UnixNano()))
	return h.Sum(nil)
}

// Sign signs the rejection proof with Conjoiner's Ed25519 private key.
func (crp *CryptographicRejectionProof) Sign(privKey ed25519.PrivateKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return errors.New("invalid private key size: expected ed25519.PrivateKey")
	}
	sig := ed25519.Sign(privKey, crp.SigningInput())
	crp.ProofSignature = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

// Verify verifies the rejection proof and its underlying receipt.
func (crp *CryptographicRejectionProof) Verify(pubKey ed25519.PublicKey) error {
	if crp.Receipt == nil {
		return errors.New("nil receipt in rejection proof")
	}
	if err := crp.Receipt.Verify(pubKey); err != nil {
		return fmt.Errorf("underlying receipt verification failed: %w", err)
	}
	if crp.Receipt.Verdict != VerdictDenyScope && crp.Receipt.Verdict != VerdictDenyDrift {
		return fmt.Errorf("receipt verdict is not a denial: %s", crp.Receipt.Verdict)
	}
	if crp.ProofSignature == "" {
		return ErrMissingSignature
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(crp.ProofSignature)
	if err != nil {
		return fmt.Errorf("%w: invalid proof signature encoding: %w", ErrInvalidSignature, err)
	}
	if !ed25519.Verify(pubKey, crp.SigningInput(), sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// RejectionError wraps a policy rejection error with its CryptographicRejectionProof.
type RejectionError struct {
	Proof *CryptographicRejectionProof
	Err   error
}

// Error formats the rejection error.
func (e *RejectionError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Proof != nil {
		return fmt.Sprintf("%v: %s", e.Err, e.Proof.Error())
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "policy rejected"
}

// Unwrap returns the underlying policy error for errors.Is matching.
func (e *RejectionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ExtractRejectionProof retrieves the CryptographicRejectionProof from an error if present.
func ExtractRejectionProof(err error) *CryptographicRejectionProof {
	var rejErr *RejectionError
	if errors.As(err, &rejErr) {
		return rejErr.Proof
	}
	var crp *CryptographicRejectionProof
	if errors.As(err, &crp) {
		return crp
	}
	return nil
}

// ComputeArgumentDigest computes the unambiguous length-prefixed SHA-256 digest of invocation arguments.
func ComputeArgumentDigest(toolName, action, resource string, args []string) string {
	h := sha256.New()
	writeLenPrefixedString(h, "conjoiner:args:v2")
	writeLenPrefixedString(h, toolName)
	writeLenPrefixedString(h, action)
	writeLenPrefixedString(h, resource)
	writeUint64BE(h, uint64(len(args)))
	for _, arg := range args {
		writeLenPrefixedString(h, arg)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateUUID generates a cryptographically random RFC 4122 v4 UUID string.
func GenerateUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
