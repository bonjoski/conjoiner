package mcp

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/bonjoski/shield/pkg/shield"
)

// Zero-width and invisible runes commonly weaponized for prompt injection smuggling.
var invisibleRunes = map[rune]bool{
	'\u200B': true, // Zero-width space
	'\u200C': true, // Zero-width non-joiner
	'\u200D': true, // Zero-width joiner
	'\uFEFF': true, // Zero-width no-break space / BOM
	'\u00AD': true, // Soft hyphen
	'\u200E': true, // Left-to-Right mark
	'\u200F': true, // Right-to-Left mark
	'\u202A': true, // LRE
	'\u202B': true, // RLE
	'\u202C': true, // PDF
	'\u202D': true, // LRO
	'\u202E': true, // RLO (Right-to-Left override)
	'\u2060': true, // Word joiner
	'\u2061': true, // Function application
	'\u2062': true, // Invisible times
	'\u2063': true, // Invisible separator
	'\u2064': true, // Invisible plus
	'\u2066': true, // LRI
	'\u2067': true, // RLI
	'\u2068': true, // FSI
	'\u2069': true, // PDI
}

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

// StripInvisibleUnicode removes invisible control runes and decodes Unicode tag character smuggling.
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

		if invisibleRunes[r] {
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
