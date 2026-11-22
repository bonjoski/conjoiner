package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExplainCommand_AllTopicsAndUnknownTopic(t *testing.T) {
	topics := []string{"dpop", "scope", "blast-radius", "kill-switch", "mcp"}
	for _, topic := range topics {
		var stdout, stderr bytes.Buffer
		code := runExplain([]string{topic, "--why"}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("runExplain(%q --why) exited %d: stderr=%s", topic, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Deep Dive (--why):") {
			t.Errorf("runExplain(%q) missing Deep Dive block:\n%s", topic, stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runExplain([]string{topic, "--json"}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("runExplain(%q --json) exited %d", topic, code)
		}
		var parsed map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
			t.Errorf("runExplain(%q --json) invalid JSON: %v", topic, err)
		}
	}

	// Default (no topic) explains dpop cleanly.
	var defOut, defErr bytes.Buffer
	if code := runExplain(nil, &defOut, &defErr); code != 0 {
		t.Fatalf("runExplain(nil) exited %d", code)
	}
	if !strings.Contains(defOut.String(), "RFC 9449") {
		t.Fatalf("expected default explain output to cover RFC 9449 DPoP, got:\n%s", defOut.String())
	}

	// Unknown topic returns exit 1 with calm Fix-Forward output.
	var unkOut, unkErr bytes.Buffer
	if code := runExplain([]string{"unknown-topic"}, &unkOut, &unkErr); code == 0 {
		t.Fatalf("expected non-zero exit code for unknown topic")
	}
	if !strings.Contains(unkErr.String(), "Unknown explain topic") {
		t.Fatalf("expected Fix-Forward error on stderr, got:\n%s", unkErr.String())
	}
}

func TestStatusCommand_DefaultWhyAndJSON(t *testing.T) {
	var out bytes.Buffer
	if code := runStatus([]string{"--why"}, &out); code != 0 {
		t.Fatalf("runStatus(--why) exited %d", code)
	}
	if !strings.Contains(out.String(), "conjoiner") || !strings.Contains(out.String(), "Why:") {
		t.Fatalf("unexpected status --why output:\n%s", out.String())
	}

	out.Reset()
	if code := runStatus([]string{"--json"}, &out); code != 0 {
		t.Fatalf("runStatus(--json) exited %d", code)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("runStatus(--json) invalid JSON: %v", err)
	}
	if parsed["tool"] != "conjoiner" {
		t.Fatalf("unexpected status JSON: %+v", parsed)
	}
}
