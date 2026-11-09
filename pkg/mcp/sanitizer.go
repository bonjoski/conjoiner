package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bonjoski/shield/pkg/shield"
)

// Regex signatures for prompt injection, jailbreaks, and system prompt override attempts.
var (
	roleMarkerRegex = regexp.MustCompile(`(?i)(</?(?:system|admin|instruction|developer|prompt|context|assistant|user)>|\[/?(?:INSTRUCTION|SYSTEM|ADMIN|DEVELOPER)\]|<<SYS>>|<</SYS>>|<\|(?:im_start|im_end|system|user|assistant)\|>)`)
	overrideRegex   = regexp.MustCompile(`(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s+override|disregard\s+(?:all\s+)?(?:prior|previous)\s+instructions|you\s+are\s+now\s+in\s+developer\s+mode|override\s+security\s+instructions)`)
)

// Sanitizer provides semantic input screening and secret redaction.
type Sanitizer struct {
	shieldEngine *shield.Engine
}

// NewSanitizer constructs an active sanitizer.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		shieldEngine: shield.NewEngine(shield.DefaultConfig()),
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

	// Check smuggled tag text if any was extracted
	if smuggled != "" {
		if loc := roleMarkerRegex.FindString(smuggled); loc != "" {
			return true, fmt.Sprintf("smuggled role marker injection detected: %s", loc)
		}
		if loc := overrideRegex.FindString(smuggled); loc != "" {
			return true, fmt.Sprintf("smuggled system override instruction detected: %s", loc)
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

// ScrubSecrets applies Shield Shannon entropy redaction to tool output.
func (s *Sanitizer) ScrubSecrets(payload []byte) ([]byte, bool) {
	if s.shieldEngine == nil {
		return payload, false
	}
	text := string(payload)
	redacted, tm, err := s.shieldEngine.Redact(text)
	if err == nil && tm != nil && tm.Count() > 0 {
		return []byte(redacted), true
	}
	return payload, false
}
