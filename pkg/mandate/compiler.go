package mandate

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
)

// Result contains the compiled scopes and AI security explanation.
type Result struct {
	Instruction string   `json:"instruction"`
	Scopes      []string `json:"scopes"`
	Advisory    string   `json:"advisory,omitempty"`
	AIAssisted  bool     `json:"ai_assisted"`
}

// Compile translates a natural language security policy or mandate into
// structured capability scopes formatted as domain:action:resource.
func Compile(ctx context.Context, instruction string, useAI bool) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	trimmed := strings.TrimSpace(instruction)
	if trimmed == "" {
		return nil, fmt.Errorf("instruction cannot be empty")
	}

	scopes := parseHeuristicScopes(trimmed)
	var advisory string

	if useAI {
		// 1. Redact candidate prompt using Shield to guarantee credential confidentiality
		engine := shield.NewEngine(shield.DefaultConfig())
		prompt := fmt.Sprintf("Translate this security mandate into Conjoiner capability scopes (format: <domain>:<action>:<resource>):\n%s", trimmed)
		redacted, _, err := engine.Redact(prompt)
		if err != nil {
			return nil, fmt.Errorf("failed shielding mandate prompt: %w", err)
		}

		// 2. Enforce fail-closed wire guard
		if err := engine.FailClosedWireGuard([]byte(redacted)); err != nil {
			return nil, fmt.Errorf("wire guard blocked outbound prompt: %w", err)
		}

		// 3. Complete with AI provider
		prov := provider.NewFromEnv()
		resp, err := prov.Complete(ctx, provider.Request{
			Model: "auto",
			Messages: []provider.Message{
				{Role: provider.RoleUser, Content: redacted},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("ai inference failed: %w", err)
		}

		advisory = resp.Content

		// Extract any valid scope tokens from AI completion
		scanner := bufio.NewScanner(strings.NewReader(resp.Content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			line = strings.Trim(line, "-*` ")
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && !strings.Contains(parts[0], " ") && (parts[0] == "fs" || parts[0] == "tool" || parts[0] == "net" || parts[0] == "env") {
				if !contains(scopes, line) {
					scopes = append(scopes, line)
				}
			}
		}
	}

	return &Result{
		Instruction: trimmed,
		Scopes:      scopes,
		Advisory:    advisory,
		AIAssisted:  useAI,
	}, nil
}

func parseHeuristicScopes(instruction string) []string {
	lower := strings.ToLower(instruction)
	scopes := make([]string, 0)

	// File system rules
	if strings.Contains(lower, "read") {
		path := extractPath(lower, "read")
		if path == "" {
			path = "."
		}
		scopes = append(scopes, fmt.Sprintf("fs:read:%s", path))
	}
	if strings.Contains(lower, "write") {
		path := extractPath(lower, "write")
		if path == "" {
			path = "."
		}
		scopes = append(scopes, fmt.Sprintf("fs:write:%s", path))
	}

	// Tool execution rules
	if strings.Contains(lower, "git") {
		if strings.Contains(lower, "git status") {
			scopes = append(scopes, "tool:exec:git:status")
		} else {
			scopes = append(scopes, "tool:exec:git:*")
		}
	} else if strings.Contains(lower, "exec") || strings.Contains(lower, "run") {
		scopes = append(scopes, "tool:exec:*")
	}

	// Network rules
	if strings.Contains(lower, "network") || strings.Contains(lower, "http") || strings.Contains(lower, "connect") {
		if !strings.Contains(lower, "deny network") && !strings.Contains(lower, "no network") {
			scopes = append(scopes, "net:connect:*")
		}
	}

	// Default fallback
	if len(scopes) == 0 {
		scopes = append(scopes, "fs:read:.")
	}

	return scopes
}

func extractPath(text, action string) string {
	idx := strings.Index(text, action)
	if idx == -1 {
		return ""
	}
	sub := text[idx+len(action):]
	words := strings.Fields(sub)
	for _, w := range words {
		w = strings.Trim(w, `",;()`)
		if strings.HasPrefix(w, "/") || strings.HasPrefix(w, "./") || strings.HasPrefix(w, "../") {
			return w
		}
	}
	return ""
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
