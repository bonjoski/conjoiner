package aiboundary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// HTTPErrorBody is the calm, minimal JSON error envelope emitted by WrapHTTPHandler.
// It never leaks stack traces, internal file paths, raw request bodies, or secrets.
type HTTPErrorBody struct {
	Error HTTPErrorDetail `json:"error"`
}

// HTTPErrorDetail provides a stable machine code and safe human message.
type HTTPErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WrapHTTPHandler enforces BlastRadiusPolicy.Authorize deterministically before next.ServeHTTP.
// Every failure mode fails closed with a structured JSON response and zero stack traces or secret leaks:
//   - 503 Service Unavailable (with Retry-After) when the 1-flip ReadOnlyKillSwitch is active
//   - 403 Forbidden on denied scope, unknown tool, exceeded call ceiling, oversized/invalid amount, or nil policy
//   - 400 Bad Request when request extraction or strict JSON validation fails
func WrapHTTPHandler(
	policy *BlastRadiusPolicy,
	extract func(*http.Request) (ToolRequest, error),
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if policy == nil {
			writeJSONError(w, http.StatusForbidden, "POLICY_UNCONFIGURED", "ai blast-radius policy is not configured")
			return
		}
		if extract == nil || next == nil {
			writeJSONError(w, http.StatusForbidden, "HANDLER_UNCONFIGURED", "deterministic middleware extractor or handler is not configured")
			return
		}

		toolReq, err := extract(r)
		if err != nil {
			switch {
			case errors.Is(err, ErrStrictJSON):
				writeJSONError(w, http.StatusBadRequest, "STRICT_JSON_FAILED", "request payload failed strict JSON schema validation")
			case errors.Is(err, ErrInvalidAmount):
				writeJSONError(w, http.StatusBadRequest, "INVALID_AMOUNT", "request contains invalid or out-of-bounds mutation amount")
			case errors.Is(err, ErrScopeDenied):
				writeJSONError(w, http.StatusForbidden, "SCOPE_DENIED", "deterministic authz denied requested tool scope")
			default:
				// Never echo raw extract errors to avoid accidentally leaking caller tokens or internal state.
				writeJSONError(w, http.StatusBadRequest, "INVALID_TOOL_REQUEST", "unable to parse deterministic tool request")
			}
			return
		}

		if err := policy.Authorize(r.Context(), toolReq); err != nil {
			switch {
			case errors.Is(err, ErrReadOnlyKillSwitch):
				w.Header().Set("Retry-After", "30")
				writeJSONError(w, http.StatusServiceUnavailable, "READ_ONLY_KILL_SWITCH", "ai tool mutation paused: read-only kill-switch enabled")
			case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				writeJSONError(w, http.StatusServiceUnavailable, "REQUEST_ABORTED", "request context canceled or timed out")
			case errors.Is(err, ErrTurnBudgetExceeded):
				writeJSONError(w, http.StatusForbidden, "TURN_BUDGET_EXCEEDED", "ai tool call ceiling exceeded for this request")
			case errors.Is(err, ErrInvalidAmount):
				writeJSONError(w, http.StatusForbidden, "INVALID_AMOUNT", "invalid or out-of-bounds mutation amount")
			default:
				writeJSONError(w, http.StatusForbidden, "SCOPE_DENIED", "deterministic authz denied requested tool scope")
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// DecodeStrictHTTPBody reads an HTTP request body up to maxBytes (defaulting to DefaultMaxJSONBytes)
// and validates it strictly into dst via ValidateStrictJSONMaxBytes (DisallowUnknownFields, no trailing tokens).
func DecodeStrictHTTPBody(r *http.Request, maxBytes int, dst any) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("%w: missing request body", ErrStrictJSON)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxJSONBytes
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
	if err != nil {
		return fmt.Errorf("%w: failed reading request body", ErrStrictJSON)
	}
	return ValidateStrictJSONMaxBytes(raw, maxBytes, dst)
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(HTTPErrorBody{
		Error: HTTPErrorDetail{
			Code:    code,
			Message: msg,
		},
	})
}

// MCPWrappedCall is the deterministic wrapper returned by WrapMCPToolCall.
// Callers supply the request context, deterministic ToolRequest metadata (derived from authenticated
// session state), raw JSON tool arguments, and an optional schemaDst struct pointer for strict
// DisallowUnknownFields decoding. When schemaDst is nil, rawArgs is still strictly verified to be
// a single well-formed JSON object within DefaultMaxJSONBytes with zero trailing tokens.
type MCPWrappedCall func(ctx context.Context, req ToolRequest, rawArgs json.RawMessage, schemaDst any) (any, error)

// WrapMCPToolCall wraps an MCP tool handler so BlastRadiusPolicy.Authorize and ValidateStrictJSON
// run deterministically before handler is ever invoked.
func WrapMCPToolCall(
	policy *BlastRadiusPolicy,
	handler func(context.Context, json.RawMessage) (any, error),
) MCPWrappedCall {
	return func(ctx context.Context, req ToolRequest, rawArgs json.RawMessage, schemaDst any) (any, error) {
		if policy == nil {
			return nil, ErrNilPolicy
		}
		if handler == nil {
			return nil, fmt.Errorf("%w: mcp tool handler is nil", ErrScopeDenied)
		}

		// 1. Deterministic blast-radius & kill-switch authorization before touching tool execution.
		if err := policy.Authorize(ctx, req); err != nil {
			return nil, err
		}

		// 2. Strict JSON validation on tool arguments (DisallowUnknownFields + size cap + no trailing tokens).
		if schemaDst != nil {
			if err := ValidateStrictJSON(rawArgs, schemaDst); err != nil {
				return nil, err
			}
		} else {
			var obj map[string]any
			if err := ValidateStrictJSON(rawArgs, &obj); err != nil {
				return nil, err
			}
			if obj == nil {
				return nil, fmt.Errorf("%w: expected non-null JSON object for MCP tool arguments", ErrStrictJSON)
			}
		}

		// 3. Execute underlying deterministic MCP tool handler.
		return handler(ctx, rawArgs)
	}
}

// WrapTypedMCPToolCall is a type-safe convenience wrapper built on WrapMCPToolCall that decodes
// raw MCP JSON arguments strictly into T (DisallowUnknownFields) before calling handler.
func WrapTypedMCPToolCall[T any](
	policy *BlastRadiusPolicy,
	handler func(context.Context, T) (any, error),
) func(ctx context.Context, req ToolRequest, rawArgs json.RawMessage) (any, error) {
	return func(ctx context.Context, req ToolRequest, rawArgs json.RawMessage) (any, error) {
		if handler == nil {
			return nil, fmt.Errorf("%w: typed mcp tool handler is nil", ErrScopeDenied)
		}
		var decoded T
		wrapped := WrapMCPToolCall(policy, func(innerCtx context.Context, _ json.RawMessage) (any, error) {
			return handler(innerCtx, decoded)
		})
		return wrapped(ctx, req, rawArgs, &decoded)
	}
}
