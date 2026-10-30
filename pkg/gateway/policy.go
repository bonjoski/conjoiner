package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
	"github.com/bonjoski/conjoiner/pkg/token"
)

var (
	// ErrScopeInsufficient indicates the token scope does not authorize the requested tool action.
	ErrScopeInsufficient = errors.New("token scope is insufficient for requested tool operation")
	// ErrPolicyViolation indicates deterministic policy rule rejection.
	ErrPolicyViolation = errors.New("deterministic policy violation")
	// ErrCommandInjectionDetected indicates detected shell metacharacters in arguments.
	ErrCommandInjectionDetected = errors.New("potential command injection detected: illegal metacharacters in arguments")
	// ErrPathTraversalDetected indicates path traversal attempt in resource path.
	ErrPathTraversalDetected = errors.New("path traversal detected: directory escape attempt")
)

// Dangerous shell metacharacters that must never be accepted in arguments.
var forbiddenMetachars = []string{
	"&", ";", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", "\x00",
}

// PolicyEngine evaluates whether a tool request is authorized deterministically.
type PolicyEngine interface {
	Evaluate(ctx context.Context, tok *token.TaskToken, execCtx ExecutionContext) error
}

// ToolRule defines deterministic constraints for a specific tool.
type ToolRule struct {
	AllowedActions   map[string]bool
	AllowedFlags     map[string]bool
	MaxArguments     int
	AllowArbitraryArgs bool
}

// DeterministicPolicyEngine implements PolicyEngine with strict compile-time allowlists.
type DeterministicPolicyEngine struct {
	toolRules map[string]ToolRule
}

// NewDeterministicPolicyEngine initializes a policy engine with default secure profiles.
func NewDeterministicPolicyEngine() *DeterministicPolicyEngine {
	rules := map[string]ToolRule{
		"git": {
			AllowedActions: map[string]bool{
				"status": true,
				"diff":   true,
				"log":    true,
				"branch": true,
				"show":   true,
			},
			AllowedFlags: map[string]bool{
				"-s": true, "--short": true, "--oneline": true, "-n": true, "-p": true,
			},
			MaxArguments:       10,
			AllowArbitraryArgs: false,
		},
		"cat": {
			AllowedActions: map[string]bool{
				"read": true,
			},
			AllowedFlags:       map[string]bool{"-n": true},
			MaxArguments:       5,
			AllowArbitraryArgs: true,
		},
		"echo": {
			AllowedActions: map[string]bool{
				"print": true,
			},
			MaxArguments:       20,
			AllowArbitraryArgs: true,
		},
	}

	return &DeterministicPolicyEngine{
		toolRules: rules,
	}
}

// RegisterToolRule adds or updates a tool rule in the policy engine.
func (e *DeterministicPolicyEngine) RegisterToolRule(toolName string, rule ToolRule) {
	e.toolRules[toolName] = rule
}

// Evaluate performs deterministic validation on the tool execution request.
func (e *DeterministicPolicyEngine) Evaluate(ctx context.Context, tok *token.TaskToken, execCtx ExecutionContext) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// 1. Argument Injection Sanitization
	for _, arg := range execCtx.Arguments {
		for _, meta := range forbiddenMetachars {
			if strings.Contains(arg, meta) {
				return fmt.Errorf("%w: argument '%s' contains forbidden metacharacter '%s'",
					ErrCommandInjectionDetected, arg, meta)
			}
		}
	}

	// 2. Path Traversal Check
	if strings.Contains(execCtx.Resource, "..") {
		return fmt.Errorf("%w: resource '%s' contains directory traversal sequence",
			ErrPathTraversalDetected, execCtx.Resource)
	}

	// 3. Token Scope Capability Check
	scopeSet, err := tok.ScopeSet()
	if err != nil {
		return fmt.Errorf("failed to parse token scopes: %w", err)
	}

	// Check candidate scopes that could authorize this action
	candidateScopes := []attenuation.Scope{
		{Raw: "*", Domain: "*", Action: "*", Resource: "*"},
		{Domain: "tool", Action: "exec", Resource: fmt.Sprintf("%s:%s", execCtx.ToolName, execCtx.Action)},
		{Domain: "tool", Action: "exec", Resource: fmt.Sprintf("%s:*", execCtx.ToolName)},
		{Domain: "tool", Action: execCtx.Action, Resource: execCtx.Resource},
		{Domain: execCtx.ToolName, Action: execCtx.Action, Resource: execCtx.Resource},
	}

	authorized := false
	for _, cand := range candidateScopes {
		if scopeSet.Contains(cand) {
			authorized = true
			break
		}
	}

	if !authorized {
		return fmt.Errorf("%w: token scopes %v do not authorize tool '%s' action '%s' on resource '%s'",
			ErrScopeInsufficient, tok.Scope, execCtx.ToolName, execCtx.Action, execCtx.Resource)
	}

	// 4. Deterministic Tool Rule Validation
	rule, exists := e.toolRules[execCtx.ToolName]
	if exists {
		// Verify action is allowed
		if len(rule.AllowedActions) > 0 && !rule.AllowedActions[execCtx.Action] {
			return fmt.Errorf("%w: action '%s' is not in allowlist for tool '%s'",
				ErrPolicyViolation, execCtx.Action, execCtx.ToolName)
		}

		// Verify max arguments
		if rule.MaxArguments > 0 && len(execCtx.Arguments) > rule.MaxArguments {
			return fmt.Errorf("%w: argument count %d exceeds maximum allowed %d for tool '%s'",
				ErrPolicyViolation, len(execCtx.Arguments), rule.MaxArguments, execCtx.ToolName)
		}
	}

	return nil
}
