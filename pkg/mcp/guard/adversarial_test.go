package guard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// rebindingResolver simulates a DNS rebinding attack where the resolver returns
// a legitimate IP on step 1 and a poisoned internal IP on step 2.
type rebindingResolver struct {
	calls    atomic.Int32
	validIP  net.IP
	poisonIP net.IP
}

func (r *rebindingResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	n := r.calls.Add(1)
	if n == 1 {
		return []net.IP{r.validIP}, nil
	}
	return []net.IP{r.poisonIP}, nil
}

func TestAdversarial_DNSRebindingDefense(t *testing.T) {
	// Custom subnet allowing 127.0.0.1 for the test server, but blocking IMDS 169.254.169.254
	customSubnets := &DefaultBlockedSubnets{
		blockedNets: []*net.IPNet{
			{IP: net.ParseIP("169.254.0.0"), Mask: net.CIDRMask(16, 32)},
		},
		reasons: []string{"IMDS link-local blocked"},
	}

	resolver := &rebindingResolver{
		validIP:  net.ParseIP("127.0.0.1"),
		poisonIP: net.ParseIP("169.254.169.254"),
	}

	transport := NewEgressGuardTransport(
		WithBlockedSubnets(customSubnets),
		WithCustomResolver(resolver),
	)
	client := &http.Client{Transport: transport}

	// 1. Initial request evaluates step 1 with valid IP
	req1, _ := http.NewRequest(http.MethodGet, "http://attacker-controlled.com/mcp", nil)
	// Transport pins the validated IP (127.0.0.1) directly into DialContext.
	// Since port 80 is not listening, dial fails locally, but it does NOT trigger an SSRF block.
	_, err := client.Do(req1)
	if err != nil && strings.Contains(err.Error(), "SSRF blocked") {
		t.Fatalf("first request was valid IP, should not be blocked as SSRF: %v", err)
	}

	// 2. Second request triggered after rebinding returns poisoned IP
	req2, _ := http.NewRequest(http.MethodGet, "http://attacker-controlled.com/mcp", nil)
	_, err = client.Do(req2)
	if err == nil {
		t.Fatal("expected DNS rebound request to be blocked by SSRF filter, but succeeded")
	}

	if !strings.Contains(err.Error(), "SSRF blocked") {
		t.Fatalf("expected SSRF block on rebound IP, got: %v", err)
	}
}

func TestAdversarial_ObfuscatedIPFormattings(t *testing.T) {
	transport := NewEgressGuardTransport()
	client := &http.Client{Transport: transport}

	obfuscatedPayloads := []struct {
		name string
		url  string
	}{
		{"Userinfo credential smuggling", "http://user:pass@169.254.169.254:80/meta-data"},
		{"Scheme case evasion", "hTtP://169.254.169.254/latest"},
		{"IPv6 mapped IPv4 with port", "http://[::ffff:169.254.169.254]:80/meta-data"},
		{"Loopback case evasion", "HTTP://127.0.0.1:8080/token"},
		{"IPv6 loopback bracket notation", "http://[::1]:8080/credentials"},
		{"Loopback subnet variation", "http://127.127.127.127:80/"},
	}

	for _, tc := range obfuscatedPayloads {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				// Malformed URL caught by parser is also acceptable defense
				return
			}

			_, err = client.Do(req)
			if err == nil {
				t.Fatalf("obfuscated target '%s' bypassed SSRF filter!", tc.url)
			}
			if !strings.Contains(err.Error(), "SSRF blocked") {
				t.Errorf("expected SSRF block, got: %v", err)
			}
		})
	}
}

// needleInHaystackResolver returns 500 clean IPs with one poisoned IP at the end.
type needleInHaystackResolver struct{}

func (n *needleInHaystackResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ips := make([]net.IP, 0, 501)
	for i := 1; i <= 500; i++ {
		ips = append(ips, net.ParseIP(fmt.Sprintf("198.51.100.%d", (i%250)+1)))
	}
	// Injected poison at tail
	ips = append(ips, net.ParseIP("169.254.169.254"))
	return ips, nil
}

func TestAdversarial_MultiIPPoisonNeedle(t *testing.T) {
	transport := NewEgressGuardTransport(WithCustomResolver(&needleInHaystackResolver{}))
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest(http.MethodGet, "http://multi-ip.target.com/mcp", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected request with poisoned tail IP to be rejected, but succeeded")
	}

	if !strings.Contains(err.Error(), "SSRF blocked") {
		t.Fatalf("expected SSRF block for needle IP, got: %v", err)
	}
}

func TestAdversarial_SymlinkTraversalManifestAudit(t *testing.T) {
	tmpDir := t.TempDir()

	// Sensitive file outside manifest directory
	secretFile := filepath.Join(tmpDir, "shadow.secret")
	if err := os.WriteFile(secretFile, []byte("NOT_A_JSON_FILE"), 0600); err != nil {
		t.Fatal(err)
	}

	// Symlink pointing to sensitive non-JSON file
	symlinkPath := filepath.Join(tmpDir, "manifest.symlink.json")
	if err := os.Symlink(secretFile, symlinkPath); err != nil {
		t.Fatal(err)
	}

	auditor := NewRegistryAuditor(nil, nil)
	_, err := auditor.AuditManifest(context.Background(), symlinkPath)
	if err == nil {
		t.Fatal("expected error auditing invalid non-JSON target reached via symlink")
	}

	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("expected JSON parse error, got: %v", err)
	}
}
