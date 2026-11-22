package aiboundary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type refundToolArgs struct {
	OrderID     string `json:"order_id"`
	AmountCents int64  `json:"amount_cents"`
	Reason      string `json:"reason"`
}

func TestWrapHTTPHandler_EnforcesStrictJSONScopeBudgetAndZeroLeak(t *testing.T) {
	policy := newTestPolicy()
	var nextCalls atomic.Int32

	extract := func(r *http.Request) (ToolRequest, error) {
		var args refundToolArgs
		if err := DecodeStrictHTTPBody(r, 64*1024, &args); err != nil {
			return ToolRequest{}, err
		}
		scopes := map[string]bool{}
		for _, s := range strings.Split(r.Header.Get("X-Caller-Scopes"), ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				scopes[s] = true
			}
		}
		mutating := r.Header.Get("X-Tool-Name") == "refund_order"
		return ToolRequest{
			ToolName:       r.Header.Get("X-Tool-Name"),
			Mutating:       mutating,
			AmountCents:    args.AmountCents,
			CallerScopes:   scopes,
			CallIndexInReq: 1,
		}, nil
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	wrapped := WrapHTTPHandler(policy, extract, next)

	// 1. Happy path -> 200 OK.
	req := httptest.NewRequest(http.MethodPost, "/tools/refund", strings.NewReader(`{"order_id":"ord_1","amount_cents":2500,"reason":"late"}`))
	req.Header.Set("X-Tool-Name", "refund_order")
	req.Header.Set("X-Caller-Scopes", "orders:read,orders:refund")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || nextCalls.Load() != 1 {
		t.Fatalf("expected 200 OK and next called once, got status=%d calls=%d body=%s", rr.Code, nextCalls.Load(), rr.Body.String())
	}

	// 2. Blocked unknown JSON field -> 400 Bad Request, next NOT called.
	req = httptest.NewRequest(http.MethodPost, "/tools/refund", strings.NewReader(`{"order_id":"ord_1","amount_cents":500,"reason":"ok","override_admin":true}`))
	req.Header.Set("X-Tool-Name", "refund_order")
	req.Header.Set("X-Caller-Scopes", "orders:refund")
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || nextCalls.Load() != 1 {
		t.Fatalf("expected 400 on unknown JSON field and next blocked, got status=%d calls=%d body=%s", rr.Code, nextCalls.Load(), rr.Body.String())
	}
	assertSafeJSONError(t, rr, "STRICT_JSON_FAILED")

	// 3. Blocked oversized refund amount -> 403 Forbidden, next NOT called.
	req = httptest.NewRequest(http.MethodPost, "/tools/refund", strings.NewReader(`{"order_id":"ord_1","amount_cents":50000,"reason":"prompt_injected"}`))
	req.Header.Set("X-Tool-Name", "refund_order")
	req.Header.Set("X-Caller-Scopes", "orders:refund")
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || nextCalls.Load() != 1 {
		t.Fatalf("expected 403 on oversized refund amount, got status=%d calls=%d body=%s", rr.Code, nextCalls.Load(), rr.Body.String())
	}
	assertSafeJSONError(t, rr, "SCOPE_DENIED")

	// 4. Blocked unauthorized caller scope -> 403 Forbidden, next NOT called.
	req = httptest.NewRequest(http.MethodPost, "/tools/refund", strings.NewReader(`{"order_id":"ord_1","amount_cents":100,"reason":"ok"}`))
	req.Header.Set("X-Tool-Name", "refund_order")
	req.Header.Set("X-Caller-Scopes", "orders:read") // missing orders:refund
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || nextCalls.Load() != 1 {
		t.Fatalf("expected 403 on unauthorized caller scope, got status=%d calls=%d body=%s", rr.Code, nextCalls.Load(), rr.Body.String())
	}
	assertSafeJSONError(t, rr, "SCOPE_DENIED")

	// 5. Secret leak hygiene: secret inside extractor error MUST NEVER appear in HTTP response!
	secretVal := "sk-proj-UltraSecretShouldNeverLeak9876543210"
	leakyExtract := func(r *http.Request) (ToolRequest, error) {
		return ToolRequest{}, fmt.Errorf("internal auth parse error with token=%s", secretVal)
	}
	rr = httptest.NewRecorder()
	WrapHTTPHandler(policy, leakyExtract, next).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/tools/refund", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on extract error, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), secretVal) || strings.Contains(rr.Body.String(), "goroutine") {
		t.Fatalf("SECURITY VIOLATION: HTTP error leaked secret or stack trace: %s", rr.Body.String())
	}

	// 6. Fail-closed on nil policy / nil extractor / nil handler (zero panics).
	for name, h := range map[string]http.Handler{
		"nil_policy":  WrapHTTPHandler(nil, extract, next),
		"nil_extract": WrapHTTPHandler(policy, nil, next),
		"nil_next":    WrapHTTPHandler(policy, extract, nil),
	} {
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/tools/refund", nil))
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403 fail-closed, got %d", name, rr.Code)
		}
	}
}

func TestWrapHTTPHandler_ConcurrentN8KillSwitchInstant503(t *testing.T) {
	policy := newTestPolicy()
	var mutatingExecsWhileReadOnly atomic.Int64

	extract := func(r *http.Request) (ToolRequest, error) {
		isMutating := r.URL.Path == "/refund"
		tool := "lookup_order"
		var amt int64
		if isMutating {
			tool = "refund_order"
			amt = 1000
		}
		return ToolRequest{
			ToolName:       tool,
			Mutating:       isMutating,
			AmountCents:    amt,
			CallerScopes:   map[string]bool{"orders:read": true, "orders:refund": true},
			CallIndexInReq: 1,
		}, nil
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	wrapped := WrapHTTPHandler(policy, extract, next)

	// Phase 1: N=8 concurrent goroutines hammering read-only and mutating routes while flipping SetReadOnly.
	const workers = 8
	const iters = 200
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if (i+id)%5 == 0 {
					policy.SetReadOnly(i%2 == 0)
				}
				// Read-only route MUST ALWAYS return 200 OK.
				roRR := httptest.NewRecorder()
				wrapped.ServeHTTP(roRR, httptest.NewRequest(http.MethodPost, "/lookup", nil))
				if roRR.Code != http.StatusOK {
					errCh <- fmt.Errorf("read-only route returned %d under kill-switch toggle", roRR.Code)
					return
				}

				// Mutating route MUST return either 200 OK or 503 Service Unavailable (never 500 or race).
				mutRR := httptest.NewRecorder()
				wrapped.ServeHTTP(mutRR, httptest.NewRequest(http.MethodPost, "/refund", nil))
				if mutRR.Code != http.StatusOK && mutRR.Code != http.StatusServiceUnavailable {
					errCh <- fmt.Errorf("mutating route returned unexpected status %d: %s", mutRR.Code, mutRR.Body.String())
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent HTTP middleware failure: %v", err)
	}

	// Phase 2: Flip SetReadOnly(true) -> prove instant 503 Service Unavailable across N=8 goroutines with 0 leaks.
	policy.SetReadOnly(true)
	guardedNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/refund" {
			mutatingExecsWhileReadOnly.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	})
	wrappedGuarded := WrapHTTPHandler(policy, extract, guardedNext)

	var wg2 sync.WaitGroup
	errCh2 := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			for i := 0; i < 100; i++ {
				rr := httptest.NewRecorder()
				wrappedGuarded.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/refund", nil))
				if rr.Code != http.StatusServiceUnavailable {
					errCh2 <- fmt.Errorf("expected 503 while kill-switch ON, got %d", rr.Code)
					return
				}
				if rr.Header().Get("Retry-After") == "" {
					errCh2 <- errors.New("expected Retry-After header on 503 kill-switch response")
					return
				}
			}
		}()
	}
	wg2.Wait()
	close(errCh2)
	for err := range errCh2 {
		t.Fatalf("kill-switch 503 invariant violated: %v", err)
	}
	if mutatingExecsWhileReadOnly.Load() != 0 {
		t.Fatalf("SECURITY VIOLATION: %d mutating HTTP calls executed while ReadOnlyKillSwitch=true", mutatingExecsWhileReadOnly.Load())
	}
}

func TestWrapMCPToolCall_EnforcesStrictJSONScopeBudgetAndConcurrentKillSwitch(t *testing.T) {
	ctx := context.Background()
	policy := newTestPolicy()
	var handlerCalls atomic.Int32

	wrapped := WrapMCPToolCall(policy, func(_ context.Context, rawArgs json.RawMessage) (any, error) {
		handlerCalls.Add(1)
		return map[string]any{"executed": true, "bytes": len(rawArgs)}, nil
	})

	validScopes := map[string]bool{"orders:read": true, "orders:refund": true}

	// 1. Happy path with strict struct schema passes.
	var dst refundToolArgs
	res, err := wrapped(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    1500,
		CallerScopes:   validScopes,
		CallIndexInReq: 1,
	}, json.RawMessage(`{"order_id":"ord_42","amount_cents":1500,"reason":"damaged"}`), &dst)
	if err != nil || res == nil || handlerCalls.Load() != 1 || dst.OrderID != "ord_42" {
		t.Fatalf("expected valid MCP call to succeed, got res=%v err=%v calls=%d dst=%+v", res, err, handlerCalls.Load(), dst)
	}

	// 2. Blocked unknown JSON field -> ErrStrictJSON, handler NOT called.
	var dstBad refundToolArgs
	_, err = wrapped(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    1000,
		CallerScopes:   validScopes,
		CallIndexInReq: 1,
	}, json.RawMessage(`{"order_id":"ord_42","amount_cents":1000,"bypass_cap":true}`), &dstBad)
	if !errors.Is(err, ErrStrictJSON) || handlerCalls.Load() != 1 {
		t.Fatalf("expected ErrStrictJSON for unknown field, got err=%v calls=%d", err, handlerCalls.Load())
	}

	// 3. Blocked concatenated trailing JSON object (even when schemaDst is nil) -> ErrStrictJSON.
	_, err = wrapped(ctx, ToolRequest{
		ToolName:       "lookup_order",
		Mutating:       false,
		CallerScopes:   validScopes,
		CallIndexInReq: 1,
	}, json.RawMessage(`{"order_id":"ord_1"}{"order_id":"ord_2"}`), nil)
	if !errors.Is(err, ErrStrictJSON) || handlerCalls.Load() != 1 {
		t.Fatalf("expected ErrStrictJSON for concatenated JSON objects, got err=%v calls=%d", err, handlerCalls.Load())
	}

	// 4. Blocked oversized refund amount -> ErrScopeDenied, handler NOT called.
	var dstOver refundToolArgs
	_, err = wrapped(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    99999,
		CallerScopes:   validScopes,
		CallIndexInReq: 1,
	}, json.RawMessage(`{"order_id":"ord_42","amount_cents":99999}`), &dstOver)
	if !errors.Is(err, ErrScopeDenied) || handlerCalls.Load() != 1 {
		t.Fatalf("expected ErrScopeDenied for oversized refund amount, got err=%v calls=%d", err, handlerCalls.Load())
	}

	// 5. Blocked unauthorized caller scope -> ErrScopeDenied, handler NOT called.
	var dstUnauth refundToolArgs
	_, err = wrapped(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    100,
		CallerScopes:   map[string]bool{"orders:read": true},
		CallIndexInReq: 1,
	}, json.RawMessage(`{"order_id":"ord_42","amount_cents":100}`), &dstUnauth)
	if !errors.Is(err, ErrScopeDenied) || handlerCalls.Load() != 1 {
		t.Fatalf("expected ErrScopeDenied for unauthorized caller scope, got err=%v calls=%d", err, handlerCalls.Load())
	}

	// 6. Typed wrapper & N=8 concurrent kill-switch enforcement.
	typedRefund := WrapTypedMCPToolCall(policy, func(_ context.Context, args refundToolArgs) (any, error) {
		return args.OrderID, nil
	})
	policy.SetReadOnly(true)
	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				if _, err := typedRefund(ctx, ToolRequest{
					ToolName:       "refund_order",
					Mutating:       true,
					AmountCents:    500,
					CallerScopes:   validScopes,
					CallIndexInReq: 1,
				}, json.RawMessage(`{"order_id":"ord_99","amount_cents":500}`)); !errors.Is(err, ErrReadOnlyKillSwitch) {
					errCh <- fmt.Errorf("worker %d: expected ErrReadOnlyKillSwitch, got %v", id, err)
					return
				}

				// Read-only MCP tool remains live during read-only kill-switch.
				if _, err := wrapped(ctx, ToolRequest{
					ToolName:       "lookup_order",
					Mutating:       false,
					CallerScopes:   validScopes,
					CallIndexInReq: 1,
				}, json.RawMessage(`{"order_id":"ord_99"}`), nil); err != nil {
					errCh <- fmt.Errorf("worker %d: expected read-only MCP tool to succeed, got %v", id, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent MCP middleware failure: %v", err)
	}
}

func assertSafeJSONError(t *testing.T, rr *httptest.ResponseRecorder, expectedCode string) {
	t.Helper()
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json Content-Type, got %q", ct)
	}
	body := bytes.TrimSpace(rr.Body.Bytes())
	var parsed HTTPErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("response is not valid structured JSON error: %v (raw: %s)", err, string(body))
	}
	if parsed.Error.Code != expectedCode {
		t.Errorf("expected error.code=%q, got %q (body: %s)", expectedCode, parsed.Error.Code, string(body))
	}
	if strings.Contains(string(body), "goroutine") || strings.Contains(string(body), ".go:") {
		t.Errorf("SECURITY VIOLATION: error body leaked stack trace: %s", string(body))
	}
}
