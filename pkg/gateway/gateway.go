package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

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
}

// ToolInvocationResponse returns sanitized output from the tool execution.
type ToolInvocationResponse struct {
	ExecutionID string           `json:"execution_id"`
	Result      *ExecutionResult `json:"result,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// Gateway intercepts and deterministically authorizes tool requests.
type Gateway struct {
	brokerPubKey ed25519.PublicKey
	replayCache  token.ReplayCache
	policyEngine PolicyEngine
	executor     ToolExecutor
}

// GatewayConfig defines dependencies for constructing a Gateway.
type GatewayConfig struct {
	BrokerPubKey ed25519.PublicKey
	ReplayCache  token.ReplayCache
	PolicyEngine PolicyEngine
	Executor     ToolExecutor
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

	return &Gateway{
		brokerPubKey: cfg.BrokerPubKey,
		replayCache:  cfg.ReplayCache,
		policyEngine: cfg.PolicyEngine,
		executor:     cfg.Executor,
	}, nil
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

	// 4. Deterministic Policy Evaluation
	execCtx := ExecutionContext{
		ToolName:  req.ToolName,
		Action:    req.Action,
		Resource:  req.Resource,
		Arguments: req.Arguments,
	}

	if err := g.policyEngine.Evaluate(ctx, tok, execCtx); err != nil {
		return nil, fmt.Errorf("policy evaluation rejected: %w", err)
	}

	// 5. Atomic Tool Execution (TOCTOU race free)
	result, err := g.executor.Execute(ctx, execCtx)
	if err != nil {
		return nil, fmt.Errorf("tool execution failed: %w", err)
	}

	return &ToolInvocationResponse{
		ExecutionID: execID,
		Result:      result,
	}, nil
}
