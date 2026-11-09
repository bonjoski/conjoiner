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
	if strings.ContainsRune(raw, '\x00') {
		return Scope{}, fmt.Errorf("%w: scope contains NUL byte", ErrInvalidScopeFormat)
	}

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
	if domain == "" || action == "" || strings.ContainsAny(domain, " \t\r\n") || strings.ContainsAny(action, " \t\r\n") {
		return Scope{}, fmt.Errorf("%w: '%s', domain and action must be non-empty", ErrInvalidScopeFormat, trimmed)
	}

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

func containsNULScope(s Scope) bool {
	return strings.ContainsRune(s.Raw, '\x00') ||
		strings.ContainsRune(s.Domain, '\x00') ||
		strings.ContainsRune(s.Action, '\x00') ||
		strings.ContainsRune(s.Resource, '\x00')
}

func hasDotDotSegment(resource string) bool {
	if resource == "" {
		return false
	}
	normalized := strings.ReplaceAll(resource, "\\", "/")
	for _, colonPart := range strings.Split(normalized, ":") {
		for _, seg := range strings.Split(colonPart, "/") {
			if seg == ".." {
				return true
			}
		}
	}
	return false
}

func isFilesystemDomain(domain string) bool {
	return domain == "fs" || domain == "file"
}

func isValidResourceWildcard(resource string, fsMode bool) bool {
	if resource == "*" {
		return true
	}
	if strings.HasSuffix(resource, "/*") {
		base := strings.TrimSuffix(resource, "/*")
		return !strings.Contains(base, "*")
	}
	if !fsMode && strings.HasSuffix(resource, ":*") {
		base := strings.TrimSuffix(resource, ":*")
		return base != "" && !strings.Contains(base, "*")
	}
	return false
}

// Covers returns true if this parent scope (s) authoritatively permits the child scope (other).
// A child scope is covered if and only if:
// 1. Neither scope contains NUL bytes or `..` traversal segments, AND
// 2. Parent is wildcard "*", OR
// 3. Domain matches (or parent domain is "*"), AND Action matches (or parent action is "*"), AND
//    Resource satisfies monotonic path containment or segment-boundary wildcard semantics (never expanding a non-wildcard parent into a wildcard child).
func (s Scope) Covers(other Scope) bool {
	if containsNULScope(s) || containsNULScope(other) {
		return false
	}
	if hasDotDotSegment(s.Resource) || hasDotDotSegment(other.Resource) {
		return false
	}

	if s.Raw == "*" || (s.Domain == "*" && s.Action == "*" && s.Resource == "*") {
		if strings.Contains(other.Resource, "*") {
			return isValidResourceWildcard(other.Resource, isFilesystemDomain(other.Domain))
		}
		return true
	}

	// Non-root parent can never cover wildcard domain or wildcard action unless parent also has "*"
	if s.Domain != "*" && s.Domain != other.Domain {
		return false
	}
	if s.Action != "*" && s.Action != other.Action {
		return false
	}

	fsMode := isFilesystemDomain(s.Domain) || isFilesystemDomain(other.Domain)

	// CRITICAL INVARIANT (CNJ-01): A non-wildcard parent resource MUST NEVER cover a child resource containing "*".
	parentIsWildcard := isValidResourceWildcard(s.Resource, fsMode)
	if strings.Contains(other.Resource, "*") {
		if !parentIsWildcard {
			return false
		}
		if !isValidResourceWildcard(other.Resource, fsMode) {
			return false
		}
	}

	// Reject malformed non-boundary wildcards on parent (e.g. "db:select:users*" or "fs:read:/tmp*")
	if strings.Contains(s.Resource, "*") && !parentIsWildcard {
		return false
	}

	// Full-resource wildcard "*" on parent
	if s.Resource == "*" {
		return other.Resource != ""
	}

	// Empty resource only matches empty resource (never acts as implicit "*")
	if s.Resource == "" || other.Resource == "" {
		return s.Resource == "" && other.Resource == ""
	}

	// Filesystem containment ("fs" or "file")
	if fsMode {
		if other.Resource == "*" {
			return false
		}
		parentHasSlashStar := strings.HasSuffix(s.Resource, "/*")
		childHasSlashStar := strings.HasSuffix(other.Resource, "/*")
		if childHasSlashStar && !parentHasSlashStar {
			return false
		}

		rawParent := s.Resource
		if parentHasSlashStar {
			rawParent = strings.TrimSuffix(s.Resource, "/*")
			if rawParent == "" {
				rawParent = "/"
			}
		}
		rawChild := other.Resource
		if childHasSlashStar {
			rawChild = strings.TrimSuffix(other.Resource, "/*")
			if rawChild == "" {
				rawChild = "/"
			}
		}

		absParent, err := filepath.Abs(filepath.Clean(rawParent))
		if err != nil {
			return false
		}
		absChild, err := filepath.Abs(filepath.Clean(rawChild))
		if err != nil {
			return false
		}

		rel, err := filepath.Rel(absParent, absChild)
		if err != nil {
			return false
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
		if rel == "." {
			return parentHasSlashStar == childHasSlashStar
		}
		return true
	}

	// Non-filesystem segment-boundary wildcard matching (":*" or "/*")
	if strings.HasSuffix(s.Resource, ":*") || strings.HasSuffix(s.Resource, "/*") {
		if other.Resource == "*" {
			return false
		}
		sep := s.Resource[len(s.Resource)-2]
		base := s.Resource[:len(s.Resource)-2]
		if base == "" {
			return false
		}
		if other.Resource == s.Resource {
			return true
		}
		target := other.Resource
		if strings.HasSuffix(target, ":*") || strings.HasSuffix(target, "/*") {
			target = target[:len(target)-2]
		}
		prefix := base + string(sep)
		return strings.HasPrefix(target, prefix) && len(target) > len(prefix)
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
