package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/bonjoski/conjoiner/pkg/ux"
)

// Standard JSON-RPC 2.0 and MCP Error Codes.
const (
	ErrCodeParseError              = -32700
	ErrCodeInvalidRequest          = -32600
	ErrCodeMethodNotFound          = -32601
	ErrCodeInvalidParams           = -32602
	ErrCodeInternalError           = -32603
	ErrCodePolicyViolation         = -32001
	ErrCodeScopeDenied             = -32002
	ErrCodeTokenExpired            = -32003
	ErrCodePromptInjectionDetected = -32004
	ErrCodeTaintViolation          = -32005
)

// UB-MCP-v1 deterministic exit codes and schema constants (RFC-2026-11-22-49).
const (
	ExitCodeOK               = 0
	ExitCodeRuntimeErr       = 1
	ExitCodePolicyDeny       = 10
	ExitCodeSupplyChainBlock = 20
	ExitCodeSandboxViolation = 30
	ExitCodeSecretGuardBlock = 40
	ExitCodeBiometricReq     = 82

	UBMCPv1SchemaVersion = "ub-cli-v2"
	ConjoinerToolName    = "conjoiner"

	// MCPDPoPMethod and MCPDPoPURI define the canonical htm/htu binding for MCP tools/call DPoP proofs.
	MCPDPoPMethod = "POST"
)

var (
	ubCodeRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	ubReceiptRe = regexp.MustCompile(`^rcpt_[0-9A-Za-z]+$`)
)

// MCPDPoPURI returns the canonical DPoP htu URI for an MCP tool invocation.
func MCPDPoPURI(toolName string) string {
	return "mcp://tools/" + strings.TrimSpace(toolName)
}

// JSONRPCMessage represents the standard JSON-RPC 2.0 envelope used by MCP.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError defines a spec-compliant error structure.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ToolCallParams defines the payload structure for `tools/call`.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolDef defines a single MCP tool definition in `tools/list`.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ToolListResult represents the result payload for `tools/list`.
type ToolListResult struct {
	Tools []ToolDef `json:"tools"`
}

// TextContent represents a standard text content block in an MCP CallToolResult.
type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult represents an MCP tools/call result supporting UB-MCP-v1 structuredContent.
type CallToolResult struct {
	Content           []TextContent `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError,omitempty"`
}

// SelfHealSuggestion defines an allowlisted self-correction hint in UB-MCP-v1.
type SelfHealSuggestion struct {
	SuggestedTool         string         `json:"suggested_tool"`
	SuggestedArgs         map[string]any `json:"suggested_args"`
	RequiresHumanApproval bool           `json:"requires_human_approval"`
}

// UBMCPv1Error conforms strictly to ub-mcp-v1-error.schema.json (additionalProperties: false).
type UBMCPv1Error struct {
	SchemaVersion  string              `json:"schema_version"`
	Tool           string              `json:"tool"`
	Code           string              `json:"code"`
	ExitCode       int                 `json:"exit_code"`
	Retryable      bool                `json:"retryable"`
	Summary        string              `json:"summary"`
	RemediationCmd string              `json:"remediation_cmd"`
	Why            string              `json:"why"`
	DeepWhy        string              `json:"deep_why,omitempty"`
	SelfHeal       *SelfHealSuggestion `json:"self_heal,omitempty"`
	ReceiptID      string              `json:"receipt_id,omitempty"`
	References     []string            `json:"references,omitempty"`
}

// FormatBLPRReceiptID converts a Conjoiner SIR ReceiptID (UUID or existing rcpt_ ID)
// into a canonical BLPR-v1 / UB-MCP-v1 receipt_id matching ^rcpt_[0-9A-Za-z]+$.
func FormatBLPRReceiptID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if ubReceiptRe.MatchString(trimmed) {
		return trimmed
	}
	trimmed = strings.TrimPrefix(trimmed, "rcpt_")
	var b strings.Builder
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "rcpt_" + b.String()
}

// sanitizeUBText removes ANSI/terminal control escapes, invisible/bidi/variation runes,
// and Plane 14 Unicode tag smuggling characters.
func sanitizeUBText(s string) string {
	stripped, _, _ := StripInvisibleUnicode(s)
	return ux.SanitizeSingleLine(stripped)
}

func truncateUBString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	var out []rune
	byteCount := 0
	for _, r := range s {
		rLen := len(string(r))
		if byteCount+rLen > maxLen-3 {
			break
		}
		out = append(out, r)
		byteCount += rLen
	}
	return strings.TrimSpace(string(out)) + "..."
}

// NewUBMCPv1ErrorResult constructs a UB-MCP-v1 compliant CallToolResult (isError: true)
// with calm <=3-line ANSI-sanitized human text and strict ub-mcp-v1-error.schema.json structuredContent.
func NewUBMCPv1ErrorResult(payload UBMCPv1Error) *CallToolResult {
	code := sanitizeUBText(strings.ToUpper(payload.Code))
	if !ubCodeRe.MatchString(code) {
		code = "CONJOINER_POLICY_DENY"
	}

	exitCode := payload.ExitCode
	switch exitCode {
	case ExitCodeRuntimeErr, ExitCodePolicyDeny, ExitCodeSupplyChainBlock,
		ExitCodeSandboxViolation, ExitCodeSecretGuardBlock, ExitCodeBiometricReq:
	default:
		exitCode = ExitCodePolicyDeny
	}

	summary := truncateUBString(sanitizeUBText(payload.Summary), 240)
	if summary == "" {
		summary = "Paused tool call by Conjoiner authorization policy."
	}

	remediation := truncateUBString(sanitizeUBText(payload.RemediationCmd), 256)
	if remediation == "" {
		remediation = "conjoiner explain scope --why"
	}

	why := truncateUBString(sanitizeUBText(payload.Why), 280)
	if why == "" {
		why = "Conjoiner enforces deterministic DPoP, monotonic scope attenuation, path containment, and taint gating before tool execution."
	}

	deepWhy := ""
	if payload.DeepWhy != "" {
		strippedDeep, _, _ := StripInvisibleUnicode(payload.DeepWhy)
		deepWhy = truncateUBString(strings.TrimSpace(ux.SanitizeTerminalText(strippedDeep)), 2048)
	}

	receiptID := FormatBLPRReceiptID(payload.ReceiptID)

	var refs []string
	for _, r := range payload.References {
		cleanRef := sanitizeUBText(r)
		if cleanRef != "" {
			refs = append(refs, cleanRef)
		}
	}

	clean := UBMCPv1Error{
		SchemaVersion:  UBMCPv1SchemaVersion,
		Tool:           ConjoinerToolName,
		Code:           code,
		ExitCode:       exitCode,
		Retryable:      payload.Retryable,
		Summary:        summary,
		RemediationCmd: remediation,
		Why:            why,
		DeepWhy:        deepWhy,
		SelfHeal:       payload.SelfHeal,
		ReceiptID:      receiptID,
		References:     refs,
	}

	calmText := fmt.Sprintf("⚠ %s: %s\n  Fix:  %s\n  Why:  %s",
		clean.Tool, clean.Summary, clean.RemediationCmd, clean.Why)

	return &CallToolResult{
		IsError:           true,
		Content:           []TextContent{{Type: "text", Text: calmText}},
		StructuredContent: clean,
	}
}

// NewSuccessResponse constructs a valid JSON-RPC 2.0 result response envelope.
func NewSuccessResponse(id json.RawMessage, result any) (*JSONRPCMessage, error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  raw,
	}, nil
}

// NewErrorResponse constructs a valid JSON-RPC error response envelope.
func NewErrorResponse(id json.RawMessage, code int, message string) *JSONRPCMessage {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
}

// NewErrorResponseWithData constructs a JSON-RPC error response carrying structured data.
func NewErrorResponseWithData(id json.RawMessage, code int, message string, data any) *JSONRPCMessage {
	msg := NewErrorResponse(id, code, message)
	if data != nil {
		if raw, err := json.Marshal(data); err == nil {
			msg.Error.Data = raw
		}
	}
	return msg
}
