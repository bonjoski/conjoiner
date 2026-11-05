package mcp

import (
	"encoding/json"
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
)

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
