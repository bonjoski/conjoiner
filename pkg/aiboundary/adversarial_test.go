package aiboundary

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
)

func newTestPolicy() *BlastRadiusPolicy {
	return &BlastRadiusPolicy{
		MaxToolCallsPerReq: 3,
		MaxMutationCents:   5000, // $50.00 hard cap
		AllowedTools: map[string]string{
			"lookup_order": "orders:read",
			"refund_order": "orders:refund",
			"update_note":  "orders:write_note",
		},
	}
}

// TestBlastRadiusPolicy_EnforcesKillSwitchBudgetAndScope satisfies RFC-2026-11-22-48
// mandatory adversarial verification across scope, budget, unknown tools, and kill-switch.
func TestBlastRadiusPolicy_EnforcesKillSwitchBudgetAndScope(t *testing.T) {
	ctx := context.Background()
	policy := newTestPolicy()

	callerScopes := map[string]bool{
		"orders:read":       true,
		"orders:refund":     true,
		"orders:write_note": true,
	}

	// 1. Happy paths within bounds.
	if err := policy.Authorize(ctx, ToolRequest{
		ToolName:       "lookup_order",
		Mutating:       false,
		AmountCents:    0,
		CallerScopes:   callerScopes,
		CallIndexInReq: 1,
	}); err != nil {
		t.Fatalf("expected read-only lookup_order to pass, got: %v", err)
	}

	if err := policy.Authorize(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    5000, // exact boundary allowed
		CallerScopes:   callerScopes,
		CallIndexInReq: 3, // exact call ceiling allowed
	}); err != nil {
		t.Fatalf("expected boundary refund_order to pass, got: %v", err)
	}

	// 2. Prompt-injected oversized amount fails closed.
	err := policy.Authorize(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    5001,
		CallerScopes:   callerScopes,
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("expected ErrScopeDenied for oversized amount, got: %v", err)
	}

	// 3. Exceeded per-request tool call budget fails closed.
	err = policy.Authorize(ctx, ToolRequest{
		ToolName:       "lookup_order",
		Mutating:       false,
		CallerScopes:   callerScopes,
		CallIndexInReq: 4,
	})
	if !errors.Is(err, ErrTurnBudgetExceeded) {
		t.Fatalf("expected ErrTurnBudgetExceeded for call index 4, got: %v", err)
	}

	// 4. Negative or zero CallIndexInReq smuggling fails closed.
	for _, badIdx := range []int{0, -1, math.MinInt} {
		err = policy.Authorize(ctx, ToolRequest{
			ToolName:       "lookup_order",
			Mutating:       false,
			CallerScopes:   callerScopes,
			CallIndexInReq: badIdx,
		})
		if !errors.Is(err, ErrTurnBudgetExceeded) {
			t.Fatalf("expected ErrTurnBudgetExceeded for smuggled call index %d, got: %v", badIdx, err)
		}
	}

	// 5. Unknown, empty, padded, or NUL-byte tool names fail closed.
	badTools := []string{
		"",
		"   ",
		"delete_all_users",
		" refund_order",
		"refund_order ",
		"refund_order\x00",
		"REFUND_ORDER",
	}
	for _, tool := range badTools {
		err = policy.Authorize(ctx, ToolRequest{
			ToolName:       tool,
			Mutating:       true,
			AmountCents:    100,
			CallerScopes:   callerScopes,
			CallIndexInReq: 1,
		})
		if !errors.Is(err, ErrScopeDenied) {
			t.Fatalf("expected ErrScopeDenied for tool %q, got: %v", tool, err)
		}
	}

	// 6. Missing or nil caller scopes fail closed.
	for _, scopes := range []map[string]bool{nil, {}, {"orders:read": true}, {"orders:refund": false}} {
		err = policy.Authorize(ctx, ToolRequest{
			ToolName:       "refund_order",
			Mutating:       true,
			AmountCents:    100,
			CallerScopes:   scopes,
			CallIndexInReq: 1,
		})
		if !errors.Is(err, ErrScopeDenied) {
			t.Fatalf("expected ErrScopeDenied for caller scopes %v, got: %v", scopes, err)
		}
	}

	// 7. 1-flip read-only kill-switch blocks mutating tools while keeping read-only live.
	policy.SetReadOnly(true)
	if !policy.IsReadOnly() {
		t.Fatalf("expected IsReadOnly() == true after SetReadOnly(true)")
	}
	err = policy.Authorize(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    100,
		CallerScopes:   callerScopes,
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrReadOnlyKillSwitch) {
		t.Fatalf("expected ErrReadOnlyKillSwitch when kill-switch active, got: %v", err)
	}
	if err := policy.Authorize(ctx, ToolRequest{
		ToolName:       "lookup_order",
		Mutating:       false,
		CallerScopes:   callerScopes,
		CallIndexInReq: 1,
	}); err != nil {
		t.Fatalf("expected read-only tool to remain available under kill-switch, got: %v", err)
	}

	// Flip kill-switch back off and confirm recovery.
	policy.SetReadOnly(false)
	if err := policy.Authorize(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    100,
		CallerScopes:   callerScopes,
		CallIndexInReq: 1,
	}); err != nil {
		t.Fatalf("expected refund_order to recover after kill-switch cleared, got: %v", err)
	}
}

func TestBlastRadiusPolicy_NegativeAndOverflowAmountSmuggling(t *testing.T) {
	ctx := context.Background()
	policy := newTestPolicy()
	scopes := map[string]bool{"orders:read": true, "orders:refund": true}

	// Negative amounts must be rejected to prevent credit-inversion / ceiling bypass.
	for _, neg := range []int64{-1, -5000, math.MinInt64} {
		err := policy.Authorize(ctx, ToolRequest{
			ToolName:       "refund_order",
			Mutating:       true,
			AmountCents:    neg,
			CallerScopes:   scopes,
			CallIndexInReq: 1,
		})
		if !errors.Is(err, ErrInvalidAmount) {
			t.Fatalf("expected ErrInvalidAmount for negative amount %d, got: %v", neg, err)
		}
	}

	// Overflow / MaxInt64 amount must fail closed.
	err := policy.Authorize(ctx, ToolRequest{
		ToolName:       "refund_order",
		Mutating:       true,
		AmountCents:    math.MaxInt64,
		CallerScopes:   scopes,
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("expected ErrScopeDenied for MaxInt64 amount, got: %v", err)
	}

	// Non-mutating tool attempting to carry a non-zero monetary amount must fail closed.
	err = policy.Authorize(ctx, ToolRequest{
		ToolName:       "lookup_order",
		Mutating:       false,
		AmountCents:    100,
		CallerScopes:   scopes,
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("expected ErrInvalidAmount for non-mutating call with non-zero amount, got: %v", err)
	}

	// Zero-budget policy allows non-monetary mutation (AmountCents == 0) but blocks any positive amount.
	zeroBudget := &BlastRadiusPolicy{
		MaxToolCallsPerReq: 2,
		MaxMutationCents:   0,
		AllowedTools:       map[string]string{"update_note": "orders:write_note"},
	}
	noteScopes := map[string]bool{"orders:write_note": true}
	if err := zeroBudget.Authorize(ctx, ToolRequest{
		ToolName:       "update_note",
		Mutating:       true,
		AmountCents:    0,
		CallerScopes:   noteScopes,
		CallIndexInReq: 1,
	}); err != nil {
		t.Fatalf("expected non-monetary mutation to pass when MaxMutationCents==0, got: %v", err)
	}
	err = zeroBudget.Authorize(ctx, ToolRequest{
		ToolName:       "update_note",
		Mutating:       true,
		AmountCents:    1,
		CallerScopes:   noteScopes,
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("expected ErrScopeDenied for positive amount when MaxMutationCents==0, got: %v", err)
	}
}

func TestBlastRadiusPolicy_FailClosedOnMisconfigurationAndCancelledContext(t *testing.T) {
	// Nil policy must fail closed.
	var nilPolicy *BlastRadiusPolicy
	if err := nilPolicy.Authorize(context.Background(), ToolRequest{ToolName: "lookup_order", CallIndexInReq: 1}); !errors.Is(err, ErrNilPolicy) {
		t.Fatalf("expected ErrNilPolicy, got: %v", err)
	}
	if !nilPolicy.IsReadOnly() {
		t.Fatalf("expected nil policy IsReadOnly() to fail closed (true)")
	}

	// Cancelled context fails closed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	policy := newTestPolicy()
	err := policy.Authorize(ctx, ToolRequest{
		ToolName:       "lookup_order",
		CallerScopes:   map[string]bool{"orders:read": true},
		CallIndexInReq: 1,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	// Empty required scope in AllowedTools fails closed.
	badScopePolicy := &BlastRadiusPolicy{
		MaxToolCallsPerReq: 2,
		AllowedTools:       map[string]string{"lookup_order": "   "},
	}
	err = badScopePolicy.Authorize(context.Background(), ToolRequest{
		ToolName:       "lookup_order",
		CallerScopes:   map[string]bool{"   ": true, "": true},
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("expected ErrScopeDenied for blank required scope, got: %v", err)
	}

	// Negative MaxMutationCents fails closed.
	negCapPolicy := &BlastRadiusPolicy{
		MaxToolCallsPerReq: 2,
		MaxMutationCents:   -100,
		AllowedTools:       map[string]string{"lookup_order": "orders:read"},
	}
	err = negCapPolicy.Authorize(context.Background(), ToolRequest{
		ToolName:       "lookup_order",
		CallerScopes:   map[string]bool{"orders:read": true},
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("expected ErrInvalidAmount for negative policy cap, got: %v", err)
	}

	// Non-positive MaxToolCallsPerReq fails closed.
	zeroCallsPolicy := &BlastRadiusPolicy{
		MaxToolCallsPerReq: 0,
		AllowedTools:       map[string]string{"lookup_order": "orders:read"},
	}
	err = zeroCallsPolicy.Authorize(context.Background(), ToolRequest{
		ToolName:       "lookup_order",
		CallerScopes:   map[string]bool{"orders:read": true},
		CallIndexInReq: 1,
	})
	if !errors.Is(err, ErrTurnBudgetExceeded) {
		t.Fatalf("expected ErrTurnBudgetExceeded for zero MaxToolCallsPerReq, got: %v", err)
	}
}

func TestValidateStrictJSON_Adversarial(t *testing.T) {
	type RefundArgs struct {
		OrderID     string `json:"order_id"`
		AmountCents int64  `json:"amount_cents"`
		Reason      string `json:"reason"`
	}

	// Valid payload passes.
	var valid RefundArgs
	if err := ValidateStrictJSON([]byte(`{"order_id":"ord_123","amount_cents":1500,"reason":"damaged"}`), &valid); err != nil {
		t.Fatalf("expected valid payload to pass, got: %v", err)
	}
	if valid.OrderID != "ord_123" || valid.AmountCents != 1500 {
		t.Fatalf("unexpected decoded struct: %+v", valid)
	}

	// Hallucinated / prompt-injected unknown field rejected.
	var dst RefundArgs
	err := ValidateStrictJSON([]byte(`{"order_id":"ord_123","amount_cents":1500,"bypass_auth":true}`), &dst)
	if !errors.Is(err, ErrStrictJSON) {
		t.Fatalf("expected ErrStrictJSON for unknown field, got: %v", err)
	}

	// Concatenated second JSON object smuggling rejected.
	err = ValidateStrictJSON([]byte(`{"order_id":"ord_1","amount_cents":100}{"order_id":"ord_2","amount_cents":999999}`), &dst)
	if !errors.Is(err, ErrStrictJSON) {
		t.Fatalf("expected ErrStrictJSON for concatenated JSON objects, got: %v", err)
	}

	// Trailing garbage rejected.
	err = ValidateStrictJSON([]byte(`{"order_id":"ord_1","amount_cents":100} trailing`), &dst)
	if !errors.Is(err, ErrStrictJSON) {
		t.Fatalf("expected ErrStrictJSON for trailing garbage, got: %v", err)
	}

	// Empty payload, nil dst, and oversized payload rejected.
	if err := ValidateStrictJSON([]byte("   "), &dst); !errors.Is(err, ErrStrictJSON) {
		t.Fatalf("expected ErrStrictJSON for empty payload, got: %v", err)
	}
	if err := ValidateStrictJSON([]byte(`{"order_id":"ord_1"}`), nil); !errors.Is(err, ErrStrictJSON) {
		t.Fatalf("expected ErrStrictJSON for nil dst, got: %v", err)
	}
	oversized := []byte(`{"order_id":"` + strings.Repeat("A", 2048) + `"}`)
	if err := ValidateStrictJSONMaxBytes(oversized, 256, &dst); !errors.Is(err, ErrStrictJSON) {
		t.Fatalf("expected ErrStrictJSON for oversized payload, got: %v", err)
	}
}

// TestBlastRadiusPolicy_ConcurrentN8KillSwitchRace stress-tests N=8 concurrent
// goroutines hammering Authorize while flipping ReadOnlyKillSwitch with zero data races.
func TestBlastRadiusPolicy_ConcurrentN8KillSwitchRace(t *testing.T) {
	ctx := context.Background()
	policy := newTestPolicy()
	scopes := map[string]bool{
		"orders:read":   true,
		"orders:refund": true,
	}

	const (
		workers    = 8
		iterations = 500
	)

	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	// 8 concurrent worker goroutines hammering Authorize while concurrently toggling ReadOnlyKillSwitch.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if (i+workerID)%7 == 0 {
					policy.ReadOnlyKillSwitch.Store(i%2 == 0)
				}

				// Read-only calls must ALWAYS succeed regardless of kill-switch state.
				if err := policy.Authorize(ctx, ToolRequest{
					ToolName:       "lookup_order",
					Mutating:       false,
					AmountCents:    0,
					CallerScopes:   scopes,
					CallIndexInReq: (i % 3) + 1,
				}); err != nil {
					errCh <- err
					return
				}

				// Mutating calls must either succeed (when switch off) or fail strictly with ErrReadOnlyKillSwitch.
				err := policy.Authorize(ctx, ToolRequest{
					ToolName:       "refund_order",
					Mutating:       true,
					AmountCents:    1000,
					CallerScopes:   scopes,
					CallIndexInReq: (i % 3) + 1,
				})
				if err != nil && !errors.Is(err, ErrReadOnlyKillSwitch) {
					errCh <- err
					return
				}

				// Over-budget calls must ALWAYS fail with ErrScopeDenied or ErrReadOnlyKillSwitch.
				err = policy.Authorize(ctx, ToolRequest{
					ToolName:       "refund_order",
					Mutating:       true,
					AmountCents:    999999,
					CallerScopes:   scopes,
					CallIndexInReq: 1,
				})
				if !errors.Is(err, ErrScopeDenied) && !errors.Is(err, ErrReadOnlyKillSwitch) {
					errCh <- errors.New("oversized mutation unexpectedly authorized under concurrency")
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent authorization invariant failed: %v", err)
	}

	// Hold kill-switch ON and prove zero mutations slip through across N=8 goroutines.
	policy.ReadOnlyKillSwitch.Store(true)
	var verifyWG sync.WaitGroup
	verifyErrCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		verifyWG.Add(1)
		go func() {
			defer verifyWG.Done()
			for i := 0; i < 200; i++ {
				err := policy.Authorize(ctx, ToolRequest{
					ToolName:       "refund_order",
					Mutating:       true,
					AmountCents:    500,
					CallerScopes:   scopes,
					CallIndexInReq: 1,
				})
				if !errors.Is(err, ErrReadOnlyKillSwitch) {
					verifyErrCh <- errors.New("mutating tool bypassed active read-only kill-switch")
					return
				}
			}
		}()
	}
	verifyWG.Wait()
	close(verifyErrCh)
	for err := range verifyErrCh {
		t.Fatalf("kill-switch enforcement failed: %v", err)
	}
}
