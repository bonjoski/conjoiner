package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/conjoiner/pkg/ledger"
	"github.com/bonjoski/conjoiner/pkg/token"
)

// ToolInvocationRequest represents the deterministic execution request.
type ToolInvocationRequest struct {
	Token     string            `json:"token"`
	DPoPProof string            `json:"dpop_proof"`
	ToolName  string            `json:"tool"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Arguments []string          `json:"arguments"`
	Headers   map[string]string `json:"headers,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
}

// ToolInvocationResponse returns sanitized output from the tool execution.
type ToolInvocationResponse struct {
	ExecutionID string                      `json:"execution_id"`
	Result      *ExecutionResult            `json:"result,omitempty"`
	Receipt     *ledger.SignedIntentReceipt `json:"receipt,omitempty"`
	Error       string                      `json:"error,omitempty"`
}

// Gateway intercepts and deterministically authorizes tool requests.
type Gateway struct {
	brokerPubKey ed25519.PublicKey
	replayCache  token.ReplayCache
	policyEngine PolicyEngine
	executor     ToolExecutor
	ledger       ledger.Ledger
}

// GatewayConfig defines dependencies for constructing a Gateway.
type GatewayConfig struct {
	BrokerPubKey ed25519.PublicKey
	ReplayCache  token.ReplayCache
	PolicyEngine PolicyEngine
	Executor     ToolExecutor
	Ledger       ledger.Ledger
}

// NewGateway constructs a new Policy Gateway instance.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.BrokerPubKey == nil {
		return nil, errors.New("broker public key is required for gateway")
	}
	if cfg.ReplayCache == nil {
		cfg.ReplayCache = token.NewMemoryReplayCache()
	}
	if cfg.PolicyEngine == nil {
		cfg.PolicyEngine = NewDeterministicPolicyEngine()
	}
	if cfg.Executor == nil {
		return nil, errors.New("tool executor is required for gateway")
	}
	if cfg.Ledger == nil {
		var err error
		cfg.Ledger, err = ledger.NewEngine(ledger.Config{InMemory: true})
		if err != nil {
			return nil, fmt.Errorf("failed initializing default ledger: %w", err)
		}
	}

	return &Gateway{
		brokerPubKey: cfg.BrokerPubKey,
		replayCache:  cfg.ReplayCache,
		policyEngine: cfg.PolicyEngine,
		executor:     cfg.Executor,
		ledger:       cfg.Ledger,
	}, nil
}

// Ledger returns the underlying Cryptographic Intent Ledger.
func (g *Gateway) Ledger() ledger.Ledger {
	return g.ledger
}

// Execute intercepts, verifies cryptographic claims, evaluates policy, and executes the tool.
// This enforces NIST Tenet #8: separation of probabilistic reasoning from deterministic tool execution.
// The downstream credentials are never passed to the caller; Conjoiner performs the execution atomically.
func (g *Gateway) Execute(ctx context.Context, req ToolInvocationRequest) (*ToolInvocationResponse, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	execID, err := token.GenerateRandomJTI()
	if err != nil {
		return nil, fmt.Errorf("failed to generate execution ID: %w", err)
	}

	now := time.Now().UTC()

	// 1. Validate Token signature and 30s TTL expiry
	tok, err := token.ParseAndVerifyToken(req.Token, g.brokerPubKey, now)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// 2. Validate DPoP Proof
	// The proof must bind to action "EXEC" and target URI "tool://<toolName>"
	expectedURI := fmt.Sprintf("tool://%s", req.ToolName)
	_, dpopJWK, err := token.ValidateProof(
		req.DPoPProof,
		"EXEC",
		expectedURI,
		req.Token, // Validates ath hash against presented token
		30*time.Second,
		g.replayCache,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("dpop proof validation failed: %w", err)
	}

	// 3. Verify DPoP Key Binding (RFC 9449: token cnf.jkt == proof JWK thumbprint)
	dpopThumbprint := dpopJWK.Thumbprint()
	if !tok.VerifyDPoPBinding(dpopThumbprint) {
		return nil, token.ErrDPoPBindingMismatch
	}

	// CNJ-06: Bind audit SessionID strictly to authenticated signed token claims (sid -> sub -> jti)
	// rather than trusting unauthenticated req.SessionID or headers.
	sessionID := strings.TrimSpace(tok.SessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(tok.Subject)
	}
	if sessionID == "" {
		sessionID = strings.TrimSpace(tok.JTI)
	}
	sessionID = ledger.SanitizeSessionID(sessionID)

	// Extract Mandate signature and DPoP signature from tokens
	mandateSig := extractJWTSignature(req.Token)
	dpopSig := extractJWTSignature(req.DPoPProof)

	// 4. Deterministic Policy Evaluation
	execCtx := ExecutionContext{
		ToolName:  req.ToolName,
		Action:    req.Action,
		Resource:  req.Resource,
		Arguments: req.Arguments,
	}

	policyErr := g.policyEngine.Evaluate(ctx, tok, execCtx)
	if policyErr != nil {
		// Policy evaluation failed: determine verdict and record CryptographicRejectionProof (CRP)
		verdict := ledger.VerdictDenyDrift
		if errors.Is(policyErr, ErrScopeInsufficient) {
			verdict = ledger.VerdictDenyScope
		}

		intent := ledger.IntentRecord{
			SessionID:        sessionID,
			AgentIdentity:    tok.Subject,
			ToolName:         req.ToolName,
			Action:           req.Action,
			Resource:         req.Resource,
			Arguments:        req.Arguments,
			MandateSignature: mandateSig,
			DPoPSignature:    dpopSig,
			Verdict:          verdict,
			RejectionReason:  policyErr.Error(),
		}

		crp, recordErr := g.ledger.RecordRejection(ctx, intent)
		if recordErr != nil {
			return nil, fmt.Errorf("policy evaluation rejected (%v) and ledger recording failed: %w", policyErr, recordErr)
		}

		// Fail closed before tool execution, returning RejectionError wrapping the original policy error
		return nil, &ledger.RejectionError{
			Proof: crp,
			Err:   fmt.Errorf("policy evaluation rejected: %w", policyErr),
		}
	}

	// 5. Policy passed: record evaluated intent and ALLOW verdict into ledger (SignedIntentReceipt)
	intent := ledger.IntentRecord{
		SessionID:        sessionID,
		AgentIdentity:    tok.Subject,
		ToolName:         req.ToolName,
		Action:           req.Action,
		Resource:         req.Resource,
		Arguments:        req.Arguments,
		MandateSignature: mandateSig,
		DPoPSignature:    dpopSig,
		Verdict:          ledger.VerdictAllow,
	}

	receipt, err := g.ledger.Record(ctx, intent)
	if err != nil {
		return nil, fmt.Errorf("failed recording intent receipt in ledger: %w", err)
	}

	// 6. Atomic Tool Execution (TOCTOU race free)
	result, err := g.executor.Execute(ctx, execCtx)
	if err != nil {
		return nil, fmt.Errorf("tool execution failed: %w", err)
	}

	return &ToolInvocationResponse{
		ExecutionID: execID,
		Result:      result,
		Receipt:     receipt,
	}, nil
}

func extractJWTSignature(jwtStr string) string {
	parts := strings.Split(jwtStr, ".")
	if len(parts) == 3 {
		return parts[2]
	}
	return jwtStr
}
