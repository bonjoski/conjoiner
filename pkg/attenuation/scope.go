package attenuation

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

var (
	// ErrEmptyScope is returned when an empty scope string is parsed.
	ErrEmptyScope = errors.New("scope cannot be empty")
	// ErrInvalidScopeFormat is returned when a scope does not conform to expected formatting.
	ErrInvalidScopeFormat = errors.New("invalid scope format")
	// ErrSupersetScopeDenied is returned when a requested scope expands privileges beyond the parent scope.
	ErrSupersetScopeDenied = errors.New("requested scope violates attenuation invariant: superset permission expansion denied")
)

// Scope represents a single structured permission capability.
// Format: <domain>:<action>:<resource> (e.g., "fs:read:/tmp/workspace", "tool:exec:git:status", "*")
type Scope struct {
	Raw      string `json:"raw"`
	Domain   string `json:"domain"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// ParseScope parses a raw scope string into a structured Scope.
func ParseScope(raw string) (Scope, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Scope{}, ErrEmptyScope
	}

	if trimmed == "*" {
		return Scope{
			Raw:      "*",
			Domain:   "*",
			Action:   "*",
			Resource: "*",
		}, nil
	}

	parts := strings.Split(trimmed, ":")
	if len(parts) < 2 {
		return Scope{}, fmt.Errorf("%w: '%s', expected at least 'domain:action'", ErrInvalidScopeFormat, trimmed)
	}

	domain := parts[0]
	action := parts[1]
	resource := ""
	if len(parts) >= 3 {
		resource = strings.Join(parts[2:], ":")
	}

	return Scope{
		Raw:      trimmed,
		Domain:   domain,
		Action:   action,
		Resource: resource,
	}, nil
}

// String returns the raw representation of the scope.
func (s Scope) String() string {
	return s.Raw
}

// Covers returns true if this parent scope (s) authoritatively permits the child scope (other).
// A child scope is covered if and only if:
// 1. Parent is wildcard "*", OR
// 2. Exact match on raw string, OR
// 3. Domain matches (or parent domain is "*"), AND Action matches (or parent action is "*"), AND
//    Resource matches with prefix/path/wildcard semantics.
func (s Scope) Covers(other Scope) bool {
	if s.Raw == "*" {
		return true
	}
	if s.Raw == other.Raw {
		return true
	}

	// Check domain
	if s.Domain != "*" && s.Domain != other.Domain {
		return false
	}

	// Check action
	if s.Action != "*" && s.Action != other.Action {
		return false
	}

	// Check resource
	if s.Resource == "*" || s.Resource == "" {
		return true
	}

	// If parent resource ends with wildcard "*", check prefix
	if strings.HasSuffix(s.Resource, "*") {
		prefix := strings.TrimSuffix(s.Resource, "*")
		return strings.HasPrefix(other.Resource, prefix)
	}

	// For filesystem domains ("fs" or "file"), check filepath containment
	if s.Domain == "fs" || s.Domain == "file" {
		parentPath := filepath.Clean(s.Resource)
		childPath := filepath.Clean(other.Resource)

		if parentPath == childPath {
			return true
		}

		rel, err := filepath.Rel(parentPath, childPath)
		if err != nil {
			return false
		}
		// If childPath is inside parentPath, rel will not start with ".." and not equal ".."
		if !strings.HasPrefix(rel, "..") && rel != "." {
			return true
		}
		return false
	}

	return s.Resource == other.Resource
}

// ScopeSet represents an immutable, deduplicated collection of scopes.
type ScopeSet struct {
	scopes []Scope
}

// NewScopeSet creates a ScopeSet from a slice of raw scope strings.
func NewScopeSet(rawScopes ...string) (ScopeSet, error) {
	seen := make(map[string]bool)
	var scopes []Scope

	for _, raw := range rawScopes {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		parsed, err := ParseScope(trimmed)
		if err != nil {
			return ScopeSet{}, fmt.Errorf("failed parsing scope '%s': %w", trimmed, err)
		}
		if !seen[parsed.Raw] {
			seen[parsed.Raw] = true
			scopes = append(scopes, parsed)
		}
	}

	sort.Slice(scopes, func(i, j int) bool {
		return scopes[i].Raw < scopes[j].Raw
	})

	return ScopeSet{scopes: scopes}, nil
}

// Scopes returns a copy of the scopes slice.
func (ss ScopeSet) Scopes() []Scope {
	out := make([]Scope, len(ss.scopes))
	copy(out, ss.scopes)
	return out
}

// Strings returns the raw string representations of the scopes.
func (ss ScopeSet) Strings() []string {
	out := make([]string, len(ss.scopes))
	for i, s := range ss.scopes {
		out[i] = s.Raw
	}
	return out
}

// Len returns the count of scopes in the set.
func (ss ScopeSet) Len() int {
	return len(ss.scopes)
}

// IsEmpty returns true if the ScopeSet contains no scopes.
func (ss ScopeSet) IsEmpty() bool {
	return len(ss.scopes) == 0
}

// Contains checks if the set contains an equivalent or broader scope covering the target.
func (ss ScopeSet) Contains(target Scope) bool {
	for _, s := range ss.scopes {
		if s.Covers(target) {
			return true
		}
	}
	return false
}

// IsSubset returns true if every scope in child is covered by at least one scope in parent.
// Enforces: ChildScope ⊆ ParentScope.
func IsSubset(child, parent ScopeSet) bool {
	if child.Len() == 0 {
		return true
	}
	if parent.Len() == 0 {
		return false
	}

	for _, c := range child.scopes {
		if !parent.Contains(c) {
			return false
		}
	}
	return true
}

// Intersect computes ChildScope = ParentScope ∩ RequestedScope.
// It returns a new ScopeSet containing all requested scopes that are authoritatively covered by parent.
func Intersect(parent, requested ScopeSet) ScopeSet {
	var allowed []Scope
	for _, req := range requested.scopes {
		if parent.Contains(req) {
			allowed = append(allowed, req)
		}
	}
	return ScopeSet{scopes: allowed}
}

// Attenuate enforces NIST agentic scope attenuation:
// It ensures that RequestedScope does not expand permissions beyond ParentScope.
// If any requested scope is NOT covered by ParentScope, it rejects with ErrSupersetScopeDenied.
// If all requested scopes are covered, it returns the attenuated ScopeSet.
func Attenuate(parent, requested ScopeSet) (ScopeSet, error) {
	if requested.Len() == 0 {
		return ScopeSet{}, nil
	}

	var violations []string
	for _, req := range requested.scopes {
		if !parent.Contains(req) {
			violations = append(violations, req.Raw)
		}
	}

	if len(violations) > 0 {
		return ScopeSet{}, fmt.Errorf("%w: unauthorized scope(s): [%s]",
			ErrSupersetScopeDenied, strings.Join(violations, ", "))
	}

	// All requested scopes are valid subsets of parent
	return requested, nil
}
