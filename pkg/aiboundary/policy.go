// Package aiboundary provides in-process deterministic blast-radius controls
// for developer applications invoking LLM tool handlers.
//
// Safe Harbor Scope: This package is strictly a local, zero-dependency Go library
// embedded inside a developer's own application process (analogous to RBAC
// middleware). It is not an inline network proxy, AI firewall, or SaaS gateway.
package aiboundary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

const (
	// DefaultMaxJSONBytes caps strict JSON decoding to prevent memory exhaustion DoS.
	DefaultMaxJSONBytes = 1 << 20 // 1 MiB
)

var (
	// ErrNilPolicy is returned when Authorize is invoked on a nil BlastRadiusPolicy.
	ErrNilPolicy = errors.New("ai blast-radius policy is nil: fail-closed")
	// ErrReadOnlyKillSwitch is returned when a mutating tool call is attempted while
	// the 1-flip read-only kill-switch is active.
	ErrReadOnlyKillSwitch = errors.New("ai tool mutation paused: read-only kill-switch enabled")
	// ErrTurnBudgetExceeded is returned when CallIndexInReq is outside [1, MaxToolCallsPerReq]
	// or MaxToolCallsPerReq is not configured positively.
	ErrTurnBudgetExceeded = errors.New("ai tool call ceiling exceeded for this request")
	// ErrScopeDenied is returned when a tool is unknown, missing required RBAC scope,
	// or exceeds the deterministic mutation budget ceiling.
	ErrScopeDenied = errors.New("deterministic authz denied requested tool scope")
	// ErrInvalidAmount is returned when AmountCents is negative, out of bounds,
	// or non-zero on a read-only tool call.
	ErrInvalidAmount = errors.New("invalid or out-of-bounds mutation amount")
	// ErrStrictJSON is returned when a tool argument payload fails strict JSON
	// schema decoding (unknown/hallucinated fields, trailing tokens, or malformed input).
	ErrStrictJSON = errors.New("strict json schema validation failed")
)

// BlastRadiusPolicy enforces hard deterministic bounds inside the developer's own
// backend so an LLM can never exceed business limits regardless of prompt injection.
//
// Once initialized, AllowedTools, MaxToolCallsPerReq, and MaxMutationCents must be
// treated as immutable; ReadOnlyKillSwitch may be flipped concurrently at runtime
// with zero locks via atomic.Bool.
type BlastRadiusPolicy struct {
	ReadOnlyKillSwitch atomic.Bool       // 1-flip feature flag degrading AI tools to read-only
	MaxToolCallsPerReq int               // e.g. 3 (must be >= 1; <= 0 fails closed)
	MaxMutationCents   int64             // e.g. 5000 ($50.00 hard cap; 0 allows only non-monetary mutations)
	AllowedTools       map[string]string // toolName -> required caller RBAC scope
}

// ToolRequest captures the deterministic authorization inputs for a single tool invocation.
type ToolRequest struct {
	ToolName       string
	Mutating       bool
	AmountCents    int64
	CallerScopes   map[string]bool
	CallIndexInReq int // 1-based index of this tool call within the current user request
}

// SetReadOnly atomically toggles the 1-flip read-only kill-switch.
func (p *BlastRadiusPolicy) SetReadOnly(enabled bool) {
	if p == nil {
		return
	}
	p.ReadOnlyKillSwitch.Store(enabled)
}

// IsReadOnly atomically reports whether the read-only kill-switch is currently enabled.
func (p *BlastRadiusPolicy) IsReadOnly() bool {
	if p == nil {
		return true // fail-closed
	}
	return p.ReadOnlyKillSwitch.Load()
}

// Authorize runs deterministically outside the LLM loop before any tool handler executes.
// Every ambiguity, misconfiguration, or boundary violation fails closed.
func (p *BlastRadiusPolicy) Authorize(ctx context.Context, req ToolRequest) error {
	if p == nil {
		return ErrNilPolicy
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("request context aborted: %w", err)
		}
	}

	// 1. Hard per-request tool-call ceiling (rejects misconfigured policy and negative/zero index smuggling).
	if p.MaxToolCallsPerReq <= 0 {
		return fmt.Errorf("%w: policy MaxToolCallsPerReq must be >= 1", ErrTurnBudgetExceeded)
	}
	if req.CallIndexInReq < 1 || req.CallIndexInReq > p.MaxToolCallsPerReq {
		return fmt.Errorf("%w: call index %d outside [1, %d]", ErrTurnBudgetExceeded, req.CallIndexInReq, p.MaxToolCallsPerReq)
	}

	// 2. Reject negative amounts and monetary amounts smuggled on read-only calls.
	if req.AmountCents < 0 {
		return fmt.Errorf("%w: negative amount %d rejected", ErrInvalidAmount, req.AmountCents)
	}
	if !req.Mutating && req.AmountCents != 0 {
		return fmt.Errorf("%w: non-zero amount %d rejected for non-mutating tool", ErrInvalidAmount, req.AmountCents)
	}
	if p.MaxMutationCents < 0 {
		return fmt.Errorf("%w: policy MaxMutationCents must be >= 0", ErrInvalidAmount)
	}

	// 3. 1-flip read-only kill-switch degradation (blocks mutations while keeping read-only tools live).
	if req.Mutating && p.ReadOnlyKillSwitch.Load() {
		return ErrReadOnlyKillSwitch
	}

	// 4. Strict tool allowlist and deterministic caller RBAC scope check.
	if req.ToolName == "" || strings.TrimSpace(req.ToolName) != req.ToolName || strings.ContainsRune(req.ToolName, '\x00') {
		return fmt.Errorf("%w: invalid or empty tool name", ErrScopeDenied)
	}
	if len(p.AllowedTools) == 0 {
		return fmt.Errorf("%w: policy AllowedTools is empty", ErrScopeDenied)
	}
	reqScope, ok := p.AllowedTools[req.ToolName]
	if !ok || strings.TrimSpace(reqScope) == "" {
		return fmt.Errorf("%w: tool %q is not allowlisted", ErrScopeDenied, req.ToolName)
	}
	if req.CallerScopes == nil || !req.CallerScopes[reqScope] {
		return fmt.Errorf("%w: caller lacks required scope %q for tool %q", ErrScopeDenied, reqScope, req.ToolName)
	}

	// 5. Hard deterministic monetary ceiling on mutating calls.
	if req.Mutating && req.AmountCents > p.MaxMutationCents {
		return fmt.Errorf("%w: mutation amount %d exceeds ceiling %d", ErrScopeDenied, req.AmountCents, p.MaxMutationCents)
	}

	return nil
}

// ValidateStrictJSON decodes raw JSON into dst using DisallowUnknownFields so
// hallucinated or prompt-injected fields fail closed, rejecting trailing tokens
// and oversized payloads (> DefaultMaxJSONBytes).
func ValidateStrictJSON(raw []byte, dst any) error {
	return ValidateStrictJSONMaxBytes(raw, DefaultMaxJSONBytes, dst)
}

// ValidateStrictJSONMaxBytes decodes raw JSON into dst with an explicit byte limit,
// strict unknown-field rejection, and trailing-payload rejection.
func ValidateStrictJSONMaxBytes(raw []byte, maxBytes int, dst any) error {
	if dst == nil {
		return fmt.Errorf("%w: destination must not be nil", ErrStrictJSON)
	}
	if maxBytes <= 0 {
		return fmt.Errorf("%w: maxBytes must be positive", ErrStrictJSON)
	}
	if len(raw) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("%w: empty json payload", ErrStrictJSON)
	}
	if len(raw) > maxBytes {
		return fmt.Errorf("%w: payload size %d exceeds limit %d", ErrStrictJSON, len(raw), maxBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", ErrStrictJSON, err)
	}

	// Reject concatenated/smuggled trailing JSON objects or garbage tokens.
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: unexpected trailing data after json object", ErrStrictJSON)
	}
	return nil
}
