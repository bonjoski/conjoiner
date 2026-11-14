package guard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockResolver struct {
	mapping map[string][]net.IP
}

func (m *mockResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if ips, ok := m.mapping[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("host not found: %s", host)
}

func TestBlockedSubnets(t *testing.T) {
	subnets := NewDefaultBlockedSubnets()

	cases := []struct {
		ip       string
		blocked  bool
		scenario string
	}{
		{"127.0.0.1", true, "IPv4 loopback"},
		{"127.1.2.3", true, "IPv4 loopback /8 range"},
		{"::1", true, "IPv6 loopback"},
		{"169.254.169.254", true, "AWS IMDSv1/v2 Link-Local"},
		{"169.254.1.1", true, "IPv4 link-local range"},
		{"fe80::1", true, "IPv6 link-local"},
		{"10.0.0.1", true, "RFC1918 Class A"},
		{"172.16.5.10", true, "RFC1918 Class B"},
		{"192.168.1.1", true, "RFC1918 Class C"},
		{"100.64.0.1", true, "Carrier Grade NAT"},
		{"fc00::1", true, "IPv6 Unique Local"},
		{"::ffff:169.254.169.254", true, "IPv4-mapped IPv6 IMDS"},
		{"::ffff:127.0.0.1", true, "IPv4-mapped IPv6 Loopback"},
		{"::ffff:10.0.0.1", true, "IPv4-mapped IPv6 RFC1918"},
		{"8.8.8.8", false, "Public Google DNS"},
		{"1.1.1.1", false, "Public Cloudflare DNS"},
		{"140.82.121.3", false, "Public GitHub IP"},
		{"2606:4700:4700::1111", false, "Public Cloudflare IPv6"},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			parsed := net.ParseIP(tc.ip)
			if parsed == nil {
				t.Fatalf("failed parsing test IP: %s", tc.ip)
			}
			isBlocked, reason := subnets.IsBlocked(parsed)
			if isBlocked != tc.blocked {
				t.Errorf("IP %s expected blocked=%v, got %v (reason: %s)", tc.ip, tc.blocked, isBlocked, reason)
			}
		})
	}
}

func TestEgressGuardTransport_DirectSSRF(t *testing.T) {
	transport := NewEgressGuardTransport()
	client := &http.Client{Transport: transport}

	ssrfTargets := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://127.0.0.1:8080/internal",
		"http://10.0.0.5/api",
		"http://192.168.1.1/router",
		"http://[::1]:9090/",
		"http://[::ffff:169.254.169.254]/meta-data",
	}

	for _, target := range ssrfTargets {
		t.Run(target, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatalf("failed creating request: %v", err)
			}

			_, err = client.Do(req)
			if err == nil {
				t.Fatalf("expected SSRF error for target %s, but request succeeded", target)
			}

			if !strings.Contains(err.Error(), "SSRF blocked") {
				t.Errorf("expected SSRF block error message, got: %v", err)
			}
		})
	}
}

func TestEgressGuardTransport_LegitimateTarget(t *testing.T) {
	// Start mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","mcp_version":"2026-11"}`))
	}))
	defer server.Close()

	// Parse server host and port
	serverURL := net.ParseIP("127.0.0.1")

	// For legitimate targets, create a custom BlockedSubnets that allows our test loopback port only
	customSubnets := &DefaultBlockedSubnets{
		blockedNets: []*net.IPNet{
			{IP: net.ParseIP("169.254.0.0"), Mask: net.CIDRMask(16, 32)},
		},
		reasons: []string{"IMDS only for this test"},
	}

	mockRes := &mockResolver{
		mapping: map[string][]net.IP{
			"mcp.legitimate.io": {serverURL},
		},
	}

	transport := NewEgressGuardTransport(
		WithBlockedSubnets(customSubnets),
		WithCustomResolver(mockRes),
	)
	client := &http.Client{Transport: transport}

	reqURL := fmt.Sprintf("http://mcp.legitimate.io:%s/mcp", strings.Split(server.Listener.Addr().String(), ":")[1])
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("legitimate request unexpectedly failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
}

func TestRegistryAuditor_AuditAndPurge(t *testing.T) {
	manifestContent := `{
  "mcpServers": {
    "clean-github": {
      "url": "https://api.github.com/mcp",
      "transport": "sse"
    },
    "poisoned-imds": {
      "url": "http://169.254.169.254/latest/meta-data/",
      "transport": "sse"
    },
    "poisoned-loopback": {
      "url": "http://127.0.0.1:9099/sse",
      "transport": "sse"
    }
  },
  "servers": [
    {
      "id": "clean-remote",
      "upstream_url": "https://remote.valid.com/api"
    },
    {
      "id": "poisoned-rfc1918",
      "upstream_url": "http://10.200.0.5:8080"
    }
  ]
}`

	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "mcp_registry.json")
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	auditor := NewRegistryAuditor(nil, nil)

	// 1. Audit Phase
	report, err := auditor.AuditManifest(context.Background(), manifestPath)
	if err != nil {
		t.Fatalf("AuditManifest failed: %v", err)
	}

	if report.TotalServers != 5 {
		t.Errorf("expected 5 total servers, got %d", report.TotalServers)
	}
	if report.PoisonedServers != 3 {
		t.Errorf("expected 3 poisoned servers, got %d", report.PoisonedServers)
	}
	if report.ValidServers != 2 {
		t.Errorf("expected 2 valid servers, got %d", report.ValidServers)
	}

	// 2. Purge Phase (Dry Run)
	dryRunResult, err := auditor.PurgePoisonedEntries(context.Background(), manifestPath, true)
	if err != nil {
		t.Fatalf("dry run purge failed: %v", err)
	}
	if dryRunResult.PurgedCount != 3 {
		t.Errorf("expected 3 purged in dry-run, got %d", dryRunResult.PurgedCount)
	}

	// 3. Purge Phase (Actual)
	purgeResult, err := auditor.PurgePoisonedEntries(context.Background(), manifestPath, false)
	if err != nil {
		t.Fatalf("actual purge failed: %v", err)
	}
	if purgeResult.PurgedCount != 3 {
		t.Errorf("expected 3 purged entries, got %d", purgeResult.PurgedCount)
	}
	if purgeResult.BackupPath == "" {
		t.Error("expected non-empty backup path")
	}

	// 4. Re-Audit Phase: must now have 0 poisoned servers
	cleanReport, err := auditor.AuditManifest(context.Background(), manifestPath)
	if err != nil {
		t.Fatalf("re-audit failed: %v", err)
	}
	if cleanReport.PoisonedServers != 0 {
		t.Errorf("expected 0 poisoned servers after purge, got %d", cleanReport.PoisonedServers)
	}
	if cleanReport.TotalServers != 2 {
		t.Errorf("expected 2 valid servers remaining, got %d", cleanReport.TotalServers)
	}
}
