package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bonjoski/conjoiner/internal/redact"
)

// Regex signatures for prompt injection, jailbreaks, system prompt overrides, and unauthorized reflection.
var (
	roleMarkerRegex = regexp.MustCompile(`(?i)(</?(?:system|admin|instruction|developer|prompt|context|assistant|user)>|\[/?(?:INSTRUCTION|SYSTEM|ADMIN|DEVELOPER)\]|<<SYS>>|<</SYS>>|<\|(?:im_start|im_end|system|user|assistant)\|>)`)
	overrideRegex   = regexp.MustCompile(`(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s+override|disregard\s+(?:all\s+)?(?:prior|previous)\s+instructions|you\s+are\s+now\s+in\s+developer\s+mode|override\s+security\s+instructions)`)
	reflectionRegex = regexp.MustCompile(`(?i)(?:(?:dump|print|reveal|leak|show|extract|export|reflect|echo|exfiltrate)\s+(?:all\s+)?(?:system\s+)?(?:env(?:ironment)?\s*(?:vars?|variables?)?|process\.env|mcp\s*(?:server\s*)?schemas?|tool\s*schemas?)|(?:env(?:ironment)?\s*(?:vars?|variables?)?|mcp\s*(?:server\s*)?schemas?|tool\s*schemas?)\s*(?:dump|leak|reflection|extraction))`)

	secretRefRegex      = regexp.MustCompile(`\[SECRET_REF_[0-9a-fA-F]{16}\]`)
	vendorSecretRegexes = []*regexp.Regexp{
		regexp.MustCompile(`\bglpat-[0-9a-zA-Z_\-]{16,}\b`),
		regexp.MustCompile(`\bgh[pousr]_[a-zA-Z0-9]{20,}\b`),
		regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b`),
		regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----|$)`),
	}
)

// Sanitizer provides semantic input screening and secret redaction.
type Sanitizer struct {
	redactEngine *redact.Engine
}

// NewSanitizer constructs an active sanitizer enriched with vendor patterns.
func NewSanitizer() *Sanitizer {
	cfg := redact.DefaultConfig()
	// Enrich built-in redaction patterns with GitLab personal access tokens
	cfg.Patterns = append(cfg.Patterns, redact.SecretPattern{
		Name:  "GitLab Personal Access Token",
		Regex: regexp.MustCompile(`\bglpat-[0-9a-zA-Z_\-]{20,}\b`),
	})
	return &Sanitizer{
		redactEngine: redact.NewEngine(cfg),
	}
}

func isInvisibleOrVariationRune(r rune) bool {
	// Unicode Variation Selectors (BMP U+FE00..U+FE0F, Ideographic U+E0100..U+E01EF, Mongolian U+180B..U+180F)
	if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) || (r >= 0x180B && r <= 0x180F) {
		return true
	}
	// Combining Grapheme Joiner and Hangul/Halfwidth invisible fillers
	switch r {
	case '\u034F', '\u115F', '\u1160', '\u3164', '\uFFA0':
		return true
	}
	// All Unicode Format (Cf) runes (includes U+00AD soft hyphen, bidi overrides/isolates, zero-width spaces/joiners, BOM)
	return unicode.Is(unicode.Cf, r)
}

// StripInvisibleUnicode removes invisible format/variation runes and decodes Plane 14 Unicode tag character smuggling.
func StripInvisibleUnicode(input string) (string, int, string) {
	if !utf8.ValidString(input) {
		input = strings.ToValidUTF8(input, "")
	}

	var b strings.Builder
	var smuggled strings.Builder
	strippedCount := 0

	for _, r := range input {
		// Unicode Tag Characters smuggling (U+E0000 to U+E007F)
		if r >= 0xE0000 && r <= 0xE007F {
			strippedCount++
			if r >= 0xE0020 && r <= 0xE007E {
				smuggled.WriteByte(byte(r - 0xE0000))
			}
			continue
		}

		if isInvisibleOrVariationRune(r) {
			strippedCount++
			continue
		}

		b.WriteRune(r)
	}

	return b.String(), strippedCount, smuggled.String()
}

// DetectPromptInjection checks both visible text and recovered smuggled text for prompt injection.
func DetectPromptInjection(input string) (bool, string) {
	cleaned, _, smuggled := StripInvisibleUnicode(input)

	// Check visible text
	if loc := roleMarkerRegex.FindString(cleaned); loc != "" {
		return true, fmt.Sprintf("role marker injection detected: %s", loc)
	}
	if loc := overrideRegex.FindString(cleaned); loc != "" {
		return true, fmt.Sprintf("system override instruction detected: %s", loc)
	}
	if loc := reflectionRegex.FindString(cleaned); loc != "" {
		return true, fmt.Sprintf("unauthorized reflection attempt detected: %s", loc)
	}

	// Check smuggled tag text if any was extracted
	if smuggled != "" {
		if loc := roleMarkerRegex.FindString(smuggled); loc != "" {
			return true, fmt.Sprintf("smuggled role marker injection detected: %s", loc)
		}
		if loc := overrideRegex.FindString(smuggled); loc != "" {
			return true, fmt.Sprintf("smuggled system override instruction detected: %s", loc)
		}
		if loc := reflectionRegex.FindString(smuggled); loc != "" {
			return true, fmt.Sprintf("smuggled unauthorized reflection attempt detected: %s", loc)
		}
	}

	return false, ""
}

// DetectJSONPromptInjection inspects both raw JSON bytes and recursively unescaped JSON string values.
func DetectJSONPromptInjection(rawJSON []byte) (bool, string) {
	if len(rawJSON) == 0 {
		return false, ""
	}
	if injected, reason := DetectPromptInjection(string(rawJSON)); injected {
		return true, reason
	}
	var decoded any
	if err := json.Unmarshal(rawJSON, &decoded); err == nil {
		if injected, reason := scanDecodedJSONStrings(decoded); injected {
			return true, reason
		}
	}
	return false, ""
}

func scanDecodedJSONStrings(v any) (bool, string) {
	switch val := v.(type) {
	case string:
		return DetectPromptInjection(val)
	case map[string]any:
		for k, item := range val {
			if injected, reason := DetectPromptInjection(k); injected {
				return true, reason
			}
			if injected, reason := scanDecodedJSONStrings(item); injected {
				return true, reason
			}
		}
	case []any:
		for _, item := range val {
			if injected, reason := scanDecodedJSONStrings(item); injected {
				return true, reason
			}
		}
	}
	return false, ""
}

func (s *Sanitizer) scrubText(text string) (string, bool) {
	modified := false

	// 1. Direct vendor credential scrubbing sweep (GitLab glpat-, GitHub ghp_, Slack xoxb-, SSH/PEM private keys)
	for _, reg := range vendorSecretRegexes {
		if reg.MatchString(text) {
			text = reg.ReplaceAllString(text, "[REDACTED_SECRET]")
			modified = true
		}
	}

	// 2. Pass through local redaction engine (handles high entropy tokens, known keys, and standard patterns with [SECRET_REF_...])
	if s.redactEngine != nil {
		redacted, tm, err := s.redactEngine.Redact(text)
		if tm != nil {
			defer tm.Zeroize()
		}
		if err == nil && tm != nil && tm.Count() > 0 {
			text = redacted
			modified = true
		}
	}

	return text, modified
}

func (s *Sanitizer) scrubJSONValue(val *any) bool {
	if val == nil || *val == nil {
		return false
	}
	switch v := (*val).(type) {
	case string:
		scrubbed, mod := s.scrubText(v)
		if mod {
			*val = scrubbed
			return true
		}
		return false
	case []any:
		modified := false
		for i := range v {
			if s.scrubJSONValue(&v[i]) {
				modified = true
			}
		}
		return modified
	case map[string]any:
		modified := false
		for k, child := range v {
			// Do not scrub protocol metadata envelope fields like _meta
			if k == "_meta" {
				continue
			}
			childVal := child
			if s.scrubJSONValue(&childVal) {
				v[k] = childVal
				modified = true
			}
		}
		return modified
	default:
		return false
	}
}

// ScrubSecrets applies Shield Shannon entropy redaction and vendor pattern scrubbing to tool output,
// ensuring raw secrets (e.g. glpat-, ghp_, xoxb-, BEGIN OPENSSH PRIVATE KEY) are replaced with [REDACTED_SECRET].
func (s *Sanitizer) ScrubSecrets(payload []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		var jsonVal any
		if err := decoder.Decode(&jsonVal); err == nil {
			modified := s.scrubJSONValue(&jsonVal)
			if modified {
				res, mErr := json.Marshal(jsonVal)
				if mErr == nil {
					return res, true
				}
			}
			return payload, false
		}
	}

	text := string(payload)
	scrubbed, modified := s.scrubText(text)
	if modified {
		return []byte(scrubbed), true
	}
	return payload, false
}
