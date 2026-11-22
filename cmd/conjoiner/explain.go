package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bonjoski/conjoiner/pkg/ux"
	"github.com/bonjoski/conjoiner/pkg/version"
)

func handleExplainCommand(args []string) {
	code := runExplain(args, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	topic := "dpop"
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--why":
			// explain always renders full --why progressive disclosure
		case "-h", "--help", "help":
			_, _ = fmt.Fprintln(stdout, "Usage: conjoiner explain [dpop|scope|blast-radius|kill-switch|mcp] [--why] [--json]")
			return 0
		default:
			if !strings.HasPrefix(a, "-") {
				topic = strings.ToLower(strings.TrimSpace(a))
			}
		}
	}

	explanations := map[string]*ux.FixForwardError{
		"dpop": {
			Tool:           "conjoiner",
			Code:           "CONJOINER_EXPLAIN_DPOP",
			Summary:        "RFC 9449 Demonstrating Proof-of-Possession (Ed25519 key-bound short-lived tokens)",
			RemediationCmd: "conjoiner dpop keygen",
			WhyOneLiner:    "Binds every 30s agent task token to an ephemeral Ed25519 keypair so stolen tokens cannot be replayed.",
			DeepWhy:        "Standard bearer tokens can be copied from logs or environment variables and reused anywhere. Conjoiner binds token.cnf.jkt to the agent's ephemeral Ed25519 DPoP keypair and enforces single-use JTI replay protection per RFC 9449 and NIST SP 800-207A.",
			References:     []string{"RFC-9449", "RFC-8693", "docs/use-cases/01-ephemeral-dpop-delegation.md"},
			ExitCode:       0,
		},
		"scope": {
			Tool:           "conjoiner",
			Code:           "CONJOINER_EXPLAIN_SCOPE",
			Summary:        "Monotonic cryptographic scope attenuation (ChildScope = ParentScope ∩ RequestedScope)",
			RemediationCmd: "conjoiner token attenuate --parent \"$TOKEN_JSON\" --requested-scope \"fs:read:./src\"",
			WhyOneLiner:    "Subagents can only narrow permissions, never escalate beyond their parent's granted capabilities.",
			DeepWhy:        "When an orchestrator delegates work to subagents via RFC 8693 Token Exchange or AgentPass attenuation, Conjoiner computes the strict intersection of parent and requested scopes (including path confinement). Any superset request fails closed immediately.",
			References:     []string{"RFC-8693", "OWASP-LLM06", "docs/use-cases/02-path-restricted-attenuation.md"},
			ExitCode:       0,
		},
		"blast-radius": {
			Tool:           "conjoiner",
			Code:           "CONJOINER_EXPLAIN_BLAST_RADIUS",
			Summary:        "In-app deterministic AI blast-radius middleware (`pkg/aiboundary` HTTP & MCP adapters)",
			RemediationCmd: "go test -race ./pkg/aiboundary/...",
			WhyOneLiner:    "Enforces hard per-request tool ceilings, strict JSON schemas, and monetary caps outside the LLM loop.",
			DeepWhy:        "Prompt instructions like 'never refund more than $50' are probabilistic and bypassable via indirect prompt injection. Embedding aiboundary.WrapHTTPHandler and WrapMCPToolCall inside your own backend guarantees <0.5ms in-process enforcement of MaxToolCallsPerReq, MaxMutationCents, AllowedTools, and DisallowUnknownFields.",
			References:     []string{"OWASP-LLM01", "OWASP-LLM06", "docs/use-cases/02-in-app-ai-blast-radius-middleware.md"},
			ExitCode:       0,
		},
		"kill-switch": {
			Tool:           "conjoiner",
			Code:           "CONJOINER_EXPLAIN_KILL_SWITCH",
			Summary:        "1-flip atomic read-only kill-switch (`BlastRadiusPolicy.SetReadOnly(true)`)",
			RemediationCmd: "conjoiner explain blast-radius --why",
			WhyOneLiner:    "Instantly pauses mutating AI tools (HTTP 503 / ErrReadOnlyKillSwitch) while keeping read-only routes live.",
			DeepWhy:        "Backed by lock-free sync/atomic.Bool, flipping policy.SetReadOnly(true) degrades mutating AI tool handlers immediately across concurrent goroutines with zero service restart and zero impact on read-only AI tools or deterministic REST/gRPC endpoints.",
			References:     []string{"OWASP-LLM06", "docs/use-cases/02-in-app-ai-blast-radius-middleware.md"},
			ExitCode:       0,
		},
		"mcp": {
			Tool:           "conjoiner",
			Code:           "CONJOINER_EXPLAIN_MCP",
			Summary:        "Deterministic MCP transport shim, manifest auditing, and in-app tool call wrapper",
			RemediationCmd: "conjoiner mcp audit --manifest ./mcp.json",
			WhyOneLiner:    "Separates probabilistic LLM tool selection from deterministic scope checks, secret scrubbing, and repo confinement.",
			DeepWhy:        "Conjoiner protects MCP servers at two complementary layers: (1) local STDIO transport shim (`conjoiner mcp-shim`) enforcing DPoP tokens, hardware presence, and Shield secret scrubbing, and (2) in-process `aiboundary.WrapMCPToolCall` validating strict JSON schemas and BlastRadiusPolicy bounds inside your own Go MCP server.",
			References:     []string{"OWASP-LLM06", "CWE-22", "docs/use-cases/02-in-app-ai-blast-radius-middleware.md"},
			ExitCode:       0,
		},
	}

	entry, ok := explanations[topic]
	if !ok {
		ffe := &ux.FixForwardError{
			Tool:           "conjoiner",
			Code:           "CONJOINER_EXPLAIN_UNKNOWN_TOPIC",
			Summary:        fmt.Sprintf("Unknown explain topic %q", topic),
			RemediationCmd: "conjoiner explain dpop",
			WhyOneLiner:    "Available topics: dpop, scope, blast-radius, kill-switch, mcp.",
			DeepWhy:        "Run `conjoiner explain <topic>` with one of: dpop, scope, blast-radius, kill-switch, mcp.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, asJSON, true)
		return 1
	}

	if err := entry.Render(stdout, asJSON, true); err != nil {
		return 1
	}
	return 0
}

func handleStatusCommand(args []string) {
	code := runStatus(args, os.Stdout)
	if code != 0 {
		os.Exit(code)
	}
}

func runStatus(args []string, stdout io.Writer) int {
	asJSON := false
	showWhy := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--why":
			showWhy = true
		case "-h", "--help", "help":
			_, _ = fmt.Fprintln(stdout, "Usage: conjoiner status [--why] [--json]")
			return 0
		}
	}

	revPath := getRevocationsFilePath()
	status := map[string]any{
		"tool":             "conjoiner",
		"version":          version.Version,
		"mode":             "local-sovereign-broker",
		"revocations_file": revPath,
		"aiboundary_ready": true,
	}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(status)
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "✓ conjoiner %s (local sovereign broker & in-app aiboundary library ready)\n", version.Version)
	if revPath != "" {
		_, _ = fmt.Fprintf(stdout, "  Revocations: %s\n", ux.SanitizeSingleLine(revPath))
	}
	if showWhy {
		_, _ = fmt.Fprintln(stdout, "  Why: Conjoiner runs 100% locally on your workstation using RFC 9449 DPoP keys and in-process aiboundary middleware (zero cloud IdP or inline proxy required).")
	}
	return 0
}
