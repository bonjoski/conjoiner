package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
)

const (
	DefaultTaintShingleSize    = 8
	DefaultEntropyThreshold    = 5.2
	MinBytesForEntropyTest     = 24
)

// TaintGate evaluates data flows between tools to prevent multi-step exfiltration.
type TaintGate interface {
	RegisterRead(sessionID, path string, data []byte)
	EvaluateEgress(sessionID, toolName string, payload []byte) (allowed bool, violationReason string)
}

// DefaultTaintGate provides in-memory dynamic taint tracking and Shannon entropy scanning.
type DefaultTaintGate struct {
	mu       sync.RWMutex
	sessions map[string][][]byte // sessionID -> list of active 8-byte shingles
}

// NewDefaultTaintGate creates an active taint gateway instance.
func NewDefaultTaintGate() *DefaultTaintGate {
	return &DefaultTaintGate{
		sessions: make(map[string][][]byte),
	}
}

// SensitiveFileSuffixes lists file patterns that trigger automated read tainting.
var SensitiveFileSuffixes = []string{
	".env",
	".key",
	".pem",
	"credentials.json",
	"id_ed25519",
	"id_rsa",
	"id_ecdsa",
	"secrets.json",
}

// IsSensitiveFile checks if a file path is considered a confidential credential source.
func IsSensitiveFile(path string) bool {
	lower := strings.ToLower(filepath.Clean(path))
	base := filepath.Base(lower)
	for _, suffix := range SensitiveFileSuffixes {
		if strings.HasSuffix(base, suffix) || base == suffix {
			return true
		}
	}
	return false
}

// EgressToolNames maps tools that transmit data outside the local workstation.
var EgressToolNames = map[string]bool{
	"fetch":        true,
	"curl":         true,
	"http_request": true,
	"webhook":      true,
	"send_message": true,
	"post":         true,
	"git_push":     true,
	"dns_query":    true,
}

// IsEgressToolName checks whether a tool name performs external egress.
func IsEgressToolName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return EgressToolNames[lower]
}

// RegisterRead extracts shingles from sensitive files and binds them to the session.
func (g *DefaultTaintGate) RegisterRead(sessionID, path string, data []byte) {
	if len(data) == 0 {
		return
	}

	var shingles [][]byte
	if len(data) < DefaultTaintShingleSize {
		shingles = append(shingles, bytes.Clone(data))
	} else {
		step := 1
		if len(data) > DefaultTaintShingleSize*64 {
			step = len(data) / (DefaultTaintShingleSize * 64)
			if step < 1 {
				step = 1
			}
		}
		for i := 0; i <= len(data)-DefaultTaintShingleSize; i += step {
			shingles = append(shingles, bytes.Clone(data[i:i+DefaultTaintShingleSize]))
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.sessions[sessionID] = append(g.sessions[sessionID], shingles...)
}

func computeEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}
	l := float64(len(data))
	var ent float64
	for _, c := range freq {
		p := c / l
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func normalizePayloadVariants(payload []byte) [][]byte {
	variants := [][]byte{payload}

	unquoted, err := url.QueryUnescape(string(payload))
	if err == nil && unquoted != string(payload) {
		variants = append(variants, []byte(unquoted))
	}

	b64Dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	if err == nil && len(b64Dec) > 0 {
		variants = append(variants, b64Dec)
	}
	b64URLDec, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(payload)))
	if err == nil && len(b64URLDec) > 0 {
		variants = append(variants, b64URLDec)
	}

	hexDec, err := hex.DecodeString(strings.TrimSpace(string(payload)))
	if err == nil && len(hexDec) > 0 {
		variants = append(variants, hexDec)
	}

	return variants
}

// EvaluateEgress validates that an outgoing tool call payload contains no leaked shingles or high-entropy derivations.
func (g *DefaultTaintGate) EvaluateEgress(sessionID, toolName string, payload []byte) (bool, string) {
	if !IsEgressToolName(toolName) {
		return true, ""
	}

	g.mu.RLock()
	shingles := g.sessions[sessionID]
	g.mu.RUnlock()

	if len(shingles) == 0 {
		return true, ""
	}

	variants := normalizePayloadVariants(payload)

	for _, v := range variants {
		// 1. Shingle exact-match
		for _, s := range shingles {
			if len(s) > 0 && bytes.Contains(v, s) {
				fp := sha256.Sum256(s)
				return false, fmt.Sprintf("taint violation: payload contains data slice [%x]", fp[:4])
			}
		}

		// 2. High-entropy payload scan
		if len(v) >= MinBytesForEntropyTest {
			ent := computeEntropy(v)
			if ent > DefaultEntropyThreshold {
				return false, fmt.Sprintf("high-entropy derivation detected (H=%.2f > %.2f)", ent, DefaultEntropyThreshold)
			}
		}
	}

	return true, ""
}
