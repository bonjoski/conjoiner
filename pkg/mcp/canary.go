package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// EnvAirlockCanaryManifest is the host-only path to Airlock's session .canaries.json manifest.
	EnvAirlockCanaryManifest = "AIRLOCK_CANARY_MANIFEST"
	maxCanaryManifestBytes   = 1 << 20
)

// ErrCanaryManifestSymlink indicates the canary manifest or its parent directory is a symlink.
var ErrCanaryManifestSymlink = errors.New("mcp: canary manifest symlink refused fail-closed")

type airlockCanaryDescriptor struct {
	SessionID   string `json:"session_id"`
	CanaryID    string `json:"canary_id"`
	Kind        string `json:"kind"`
	Prefix      string `json:"prefix"`
	ValueSHA256 string `json:"value_sha256"`
	Token       string `json:"token"`
	PlantedRel  string `json:"planted_rel"`
}

type airlockCanaryManifest struct {
	Version   string                    `json:"version"`
	SessionID string                    `json:"session_id"`
	PID       int                       `json:"pid"`
	Canaries  []airlockCanaryDescriptor `json:"canaries"`
}

// CanaryMatch describes a detected canary tripwire hit without exposing raw secret bytes.
type CanaryMatch struct {
	CanaryID    string
	Kind        string
	SessionID   string
	ValueSHA256 string
	Encoding    string
}

type canaryPattern struct {
	needle      []byte
	canaryID    string
	kind        string
	sessionID   string
	valueSHA256 string
	encoding    string
}

// CanaryGuard performs lock-free O(n) scanning of MCP JSON-RPC tool arguments against
// Airlock's host-only .canaries.json manifest (raw, lowercase, hex, Base64, URL-encoded).
type CanaryGuard struct {
	patterns        []canaryPattern
	manifestPID     int
	argusSocketPath string
}

// LoadCanaryGuard safely loads an Airlock .canaries.json manifest via os.OpenRoot,
// refusing symlinks and oversized files fail-closed.
func LoadCanaryGuard(manifestPath, argusSocketPath string) (*CanaryGuard, error) {
	cleaned := strings.TrimSpace(manifestPath)
	if cleaned == "" {
		return nil, nil
	}

	dir := filepath.Dir(cleaned)
	base := filepath.Base(cleaned)
	if base == "" || base == "." || base == ".." {
		return nil, fmt.Errorf("mcp: invalid canary manifest path %q", manifestPath)
	}

	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("mcp: failed lstat canary manifest dir: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return nil, fmt.Errorf("%w: directory %s", ErrCanaryManifestSymlink, dir)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("mcp: failed opening canary manifest root: %w", err)
	}
	defer func() { _ = root.Close() }()

	fi, err := root.Lstat(base)
	if err != nil {
		return nil, fmt.Errorf("mcp: failed lstat canary manifest: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: file %s", ErrCanaryManifestSymlink, cleaned)
	}

	f, err := root.Open(base)
	if err != nil {
		return nil, fmt.Errorf("mcp: failed opening canary manifest: %w", err)
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(io.LimitReader(f, maxCanaryManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("mcp: failed reading canary manifest: %w", err)
	}
	if int64(len(raw)) > maxCanaryManifestBytes {
		return nil, fmt.Errorf("mcp: canary manifest exceeds %d bytes", maxCanaryManifestBytes)
	}

	var manifest airlockCanaryManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("mcp: invalid canary manifest JSON: %w", err)
	}

	patterns := make([]canaryPattern, 0, len(manifest.Canaries)*6)
	seen := make(map[string]bool, len(manifest.Canaries)*6)
	add := func(d airlockCanaryDescriptor, enc, needle string) {
		if needle == "" || seen[needle] {
			return
		}
		seen[needle] = true
		sessID := d.SessionID
		if sessID == "" {
			sessID = manifest.SessionID
		}
		patterns = append(patterns, canaryPattern{
			needle:      []byte(needle),
			canaryID:    d.CanaryID,
			kind:        d.Kind,
			sessionID:   sessID,
			valueSHA256: d.ValueSHA256,
			encoding:    enc,
		})
	}

	for _, c := range manifest.Canaries {
		tok := strings.TrimSpace(c.Token)
		if tok == "" {
			continue
		}
		add(c, "raw", tok)
		if lower := strings.ToLower(tok); lower != tok {
			add(c, "raw_lower", lower)
		}
		add(c, "hex", hex.EncodeToString([]byte(tok)))
		b64Std := base64.RawStdEncoding.EncodeToString([]byte(tok))
		add(c, "base64", b64Std)
		if b64Lower := strings.ToLower(b64Std); b64Lower != b64Std {
			add(c, "base64_lower", b64Lower)
		}
		add(c, "base64url", base64.RawURLEncoding.EncodeToString([]byte(tok)))
		if urlEsc := url.QueryEscape(tok); urlEsc != tok {
			add(c, "url", urlEsc)
		}
	}

	return &CanaryGuard{
		patterns:        patterns,
		manifestPID:     manifest.PID,
		argusSocketPath: strings.TrimSpace(argusSocketPath),
	}, nil
}

// Match scans payload lock-free against precomputed canary patterns.
func (g *CanaryGuard) Match(payload []byte) (CanaryMatch, bool) {
	if g == nil || len(payload) == 0 || len(g.patterns) == 0 {
		return CanaryMatch{}, false
	}
	for _, pat := range g.patterns {
		if bytes.Contains(payload, pat.needle) {
			return CanaryMatch{
				CanaryID:    pat.canaryID,
				Kind:        pat.kind,
				SessionID:   pat.sessionID,
				ValueSHA256: pat.valueSHA256,
				Encoding:    pat.encoding,
			}, true
		}
	}
	lowerPayload := bytes.ToLower(payload)
	for _, pat := range g.patterns {
		if pat.encoding == "raw_lower" || pat.encoding == "hex" || pat.encoding == "base64_lower" {
			if bytes.Contains(lowerPayload, pat.needle) {
				return CanaryMatch{
					CanaryID:    pat.canaryID,
					Kind:        pat.kind,
					SessionID:   pat.sessionID,
					ValueSHA256: pat.valueSHA256,
					Encoding:    pat.encoding,
				}, true
			}
		}
	}
	return CanaryMatch{}, false
}

// MatchJSON scans both raw JSON bytes and recursively decoded JSON strings/keys to defeat
// JSON Unicode-escape evasion (e.g. "\u0041KIATRIP...").
func (g *CanaryGuard) MatchJSON(raw []byte) (CanaryMatch, bool) {
	if m, ok := g.Match(raw); ok {
		return m, true
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return CanaryMatch{}, false
	}
	return g.matchDecodedValue(decoded)
}

func (g *CanaryGuard) matchDecodedValue(v any) (CanaryMatch, bool) {
	switch node := v.(type) {
	case string:
		return g.Match([]byte(node))
	case map[string]any:
		for k, val := range node {
			if m, ok := g.Match([]byte(k)); ok {
				return m, true
			}
			if m, ok := g.matchDecodedValue(val); ok {
				return m, true
			}
		}
	case []any:
		for _, item := range node {
			if m, ok := g.matchDecodedValue(item); ok {
				return m, true
			}
		}
	}
	return CanaryMatch{}, false
}

// EmitArgusAlert sends a best-effort non-blocking CANARY_TRIPWIRE_TRIGGERED telemetry alert
// over ~/.argus/argus.sock (never transmitting raw canary secret values).
func (g *CanaryGuard) EmitArgusAlert(match CanaryMatch, toolName string) {
	if g == nil {
		return
	}
	sockPath := g.argusSocketPath
	if sockPath == "" {
		if envSock := strings.TrimSpace(os.Getenv("ARGUS_SOCKET")); envSock != "" {
			sockPath = envSock
		} else if home, err := os.UserHomeDir(); err == nil && home != "" {
			sockPath = filepath.Join(home, ".argus", "argus.sock")
		}
	}
	if sockPath == "" {
		return
	}
	telemetry := map[string]any{
		"timestamp":  time.Now().UTC(),
		"source":     "conjoiner",
		"event_type": "CANARY_TRIPWIRE_TRIGGERED",
		"severity":   "CRITICAL",
		"details": map[string]any{
			"vector":       "mcp_tools_call",
			"tool_name":    sanitizeSafeToolLabel(toolName),
			"canary_id":    match.CanaryID,
			"kind":         match.Kind,
			"session_id":   match.SessionID,
			"value_sha256": match.ValueSHA256,
			"encoding":     match.Encoding,
		},
	}
	if g.manifestPID > 0 {
		telemetry["target_pid"] = g.manifestPID
	}
	payload, err := json.Marshal(map[string]any{
		"action":    "telemetry_ingest",
		"telemetry": telemetry,
	})
	if err != nil {
		return
	}
	conn, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Write(append(payload, '\n'))
}
