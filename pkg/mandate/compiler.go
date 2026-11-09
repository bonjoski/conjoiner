package mandate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
)

var (
	// ErrNegatedDirective indicates the mandate contains a negated/prohibitive directive
	// that either grants no positive capabilities or carves an unrepresentable negative hole inside a broader grant.
	ErrNegatedDirective = errors.New("mandate contains negated or prohibitive directive")
	// ErrEmptyCeiling indicates CompileWithCeiling was invoked with an empty ceiling ScopeSet.
	ErrEmptyCeiling = errors.New("mandate ceiling scope set cannot be empty")
)

var negationWords = map[string]bool{
	"not":        true,
	"no":         true,
	"never":      true,
	"deny":       true,
	"denied":     true,
	"forbid":     true,
	"forbidden":  true,
	"prohibit":   true,
	"prohibited": true,
	"disallow":   true,
	"disallowed": true,
	"without":    true,
	"except":     true,
	"unless":     true,
	"block":      true,
	"blocked":    true,
	"refuse":     true,
	"prevent":    true,
	"cannot":     true,
	"can't":      true,
	"cant":       true,
	"don't":      true,
	"dont":       true,
	"mustn't":    true,
	"won't":      true,
	"wont":       true,
}

// Result contains the compiled scopes and AI security explanation.
type Result struct {
	Instruction string   `json:"instruction"`
	Scopes      []string `json:"scopes"`
	Advisory    string   `json:"advisory,omitempty"`
	AIAssisted  bool     `json:"ai_assisted"`
}

// CompileWithCeiling translates a natural language security mandate into structured capability scopes
// and strictly intersects the output against the caller-supplied ceiling ScopeSet (CNJ-05):
// CompiledScopes = Ceiling ∩ CandidateScopes.
func CompileWithCeiling(ctx context.Context, instruction string, useAI bool, ceiling attenuation.ScopeSet) (*Result, error) {
	if ceiling.IsEmpty() {
		return nil, ErrEmptyCeiling
	}

	res, err := Compile(ctx, instruction, useAI)
	if err != nil {
		return nil, err
	}

	candSet, err := attenuation.NewScopeSet(res.Scopes...)
	if err != nil {
		return nil, fmt.Errorf("invalid compiled candidate scopes: %w", err)
	}

	bounded := attenuation.Intersect(ceiling, candSet)
	res.Scopes = bounded.Strings()
	return res, nil
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

	scopes, deniedScopes, err := parseHeuristicScopesStrict(trimmed)
	if err != nil {
		return nil, err
	}

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

		// Extract valid scope tokens from AI completion, subject to heuristic ceiling & deny-list checks
		heuristicCeiling, _ := attenuation.NewScopeSet(scopes...)
		scanner := bufio.NewScanner(strings.NewReader(resp.Content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			line = strings.Trim(line, "-*` ")
			if line == "" || line == "*" {
				continue
			}
			parsed, parseErr := attenuation.ParseScope(line)
			if parseErr != nil {
				continue
			}
			if parsed.Domain != "fs" && parsed.Domain != "tool" && parsed.Domain != "net" && parsed.Domain != "env" {
				continue
			}
			if conflictsWithDenied(parsed, deniedScopes) {
				continue
			}
			// Never allow unverified LLM output to escalate beyond what the mandate text itself authorized
			if !heuristicCeiling.IsEmpty() && !heuristicCeiling.Contains(parsed) {
				continue
			}
			if !contains(scopes, parsed.Raw) {
				scopes = append(scopes, parsed.Raw)
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

func splitMandateClauses(instruction string) []string {
	lower := strings.ToLower(instruction)
	// Insert explicit clause break markers (`|`) before conjunctive/exception transitions
	replacer := strings.NewReplacer(
		";", " | ",
		"\n", " | ",
		",", " | ",
		". ", " | ",
		" but ", " | ",
		" however ", " | ",
		" while ", " | ",
		" except ", " | except ",
		" without ", " | without ",
		" unless ", " | unless ",
		" and not ", " | not ",
		" and never ", " | never ",
		" and do not ", " | do not ",
		" and don't ", " | don't ",
		" and dont ", " | dont ",
		" and deny ", " | deny ",
		" and forbid ", " | forbid ",
		" and disallow ", " | disallow ",
		" and prohibit ", " | prohibit ",
		" and no ", " | no ",
	)
	segmented := replacer.Replace(lower)
	rawParts := strings.Split(segmented, "|")
	var clauses []string
	for _, p := range rawParts {
		if c := strings.TrimSpace(p); c != "" {
			clauses = append(clauses, c)
		}
	}
	return clauses
}

func clauseIsNegated(clause string) bool {
	tokens := strings.FieldsFunc(clause, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '\''
	})
	for _, tok := range tokens {
		if negationWords[tok] {
			return true
		}
	}
	return false
}

func extractClauseScopes(clause string, negated bool) ([]string, error) {
	var out []string

	if strings.Contains(clause, "read") {
		path, err := extractSafePath(clause, "read")
		if err != nil {
			return nil, err
		}
		if path == "" {
			if negated {
				path = "*"
			} else {
				path = "."
			}
		}
		out = append(out, fmt.Sprintf("fs:read:%s", path))
	}

	if strings.Contains(clause, "write") {
		path, err := extractSafePath(clause, "write")
		if err != nil {
			return nil, err
		}
		if path == "" {
			if negated {
				path = "*"
			} else {
				path = "."
			}
		}
		out = append(out, fmt.Sprintf("fs:write:%s", path))
	}

	// If negated exception clause mentions a path without an explicit read/write verb (e.g. "except /workspace/secrets")
	if negated && len(out) == 0 {
		if p, err := extractAnyPath(clause); err != nil {
			return nil, err
		} else if p != "" {
			out = append(out, fmt.Sprintf("fs:read:%s", p), fmt.Sprintf("fs:write:%s", p))
		}
	}

	if strings.Contains(clause, "git") {
		if strings.Contains(clause, "git status") {
			out = append(out, "tool:exec:git:status")
		} else {
			out = append(out, "tool:exec:git:*")
		}
	} else if strings.Contains(clause, "exec") || strings.Contains(clause, "run") {
		out = append(out, "tool:exec:*")
	}

	if strings.Contains(clause, "network") || strings.Contains(clause, "http") || strings.Contains(clause, "connect") {
		out = append(out, "net:connect:*")
	}

	return out, nil
}

func conflictsWithDenied(cand attenuation.Scope, denied []attenuation.Scope) bool {
	for _, d := range denied {
		// Either the denied scope covers the candidate OR the candidate is broader than and covers the denied target!
		if d.Covers(cand) || cand.Covers(d) {
			return true
		}
	}
	return false
}

func parseHeuristicScopesStrict(instruction string) ([]string, []attenuation.Scope, error) {
	clauses := splitMandateClauses(instruction)
	var positiveRaw []string
	var denied []attenuation.Scope
	sawNegation := false

	for _, clause := range clauses {
		if clauseIsNegated(clause) {
			sawNegation = true
			negScopes, err := extractClauseScopes(clause, true)
			if err != nil {
				return nil, nil, err
			}
			for _, ns := range negScopes {
				if parsed, pErr := attenuation.ParseScope(ns); pErr == nil {
					denied = append(denied, parsed)
				}
			}
			continue
		}

		posScopes, err := extractClauseScopes(clause, false)
		if err != nil {
			return nil, nil, err
		}
		for _, ps := range posScopes {
			if !contains(positiveRaw, ps) {
				positiveRaw = append(positiveRaw, ps)
			}
		}
	}

	// CNJ-05: If mandate had negated/prohibitive directives and zero positive grants (e.g. "NEVER write to /etc"), fail closed!
	if sawNegation && len(positiveRaw) == 0 {
		return nil, nil, fmt.Errorf("%w: prohibitive instruction grants no positive capabilities", ErrNegatedDirective)
	}

	// Check that no positive scope covers or is covered by an explicitly denied scope (e.g. "Read /ws except /ws/secret")
	var filtered []string
	for _, raw := range positiveRaw {
		parsed, err := attenuation.ParseScope(raw)
		if err != nil {
			return nil, nil, err
		}
		if conflictsWithDenied(parsed, denied) {
			return nil, nil, fmt.Errorf("%w: positive scope '%s' conflicts with negated exclusion in mandate", ErrNegatedDirective, raw)
		}
		filtered = append(filtered, parsed.Raw)
	}

	if len(filtered) == 0 {
		filtered = append(filtered, "fs:read:.")
	}

	return filtered, denied, nil
}

func extractSafePath(text, action string) (string, error) {
	idx := strings.Index(text, action)
	if idx == -1 {
		return "", nil
	}
	sub := text[idx+len(action):]
	return extractAnyPath(sub)
}

func extractAnyPath(sub string) (string, error) {
	words := strings.Fields(sub)
	for _, w := range words {
		w = strings.Trim(w, `",;().`)
		if strings.HasPrefix(w, "../") || strings.Contains(w, "/..") {
			return "", fmt.Errorf("%w: directory traversal '%s' is forbidden in mandates", attenuation.ErrInvalidScopeFormat, w)
		}
		if strings.HasPrefix(w, "/") || strings.HasPrefix(w, "./") {
			return w, nil
		}
	}
	return "", nil
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
