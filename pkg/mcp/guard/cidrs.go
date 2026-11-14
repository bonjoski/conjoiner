package guard

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// BlockedSubnets defines the contract for IP blocking rules.
type BlockedSubnets interface {
	IsBlocked(ip net.IP) (bool, string)
}

// DefaultBlockedSubnets implements BlockedSubnets using canonical security blocklists.
type DefaultBlockedSubnets struct {
	blockedNets []*net.IPNet
	reasons     []string
}

// NewDefaultBlockedSubnets initializes default blocked CIDRs covering:
// - RFC 1918 Private Subnets
// - Loopback (IPv4 & IPv6)
// - Link-Local / AWS IMDS (169.254.0.0/16, fe80::/10)
// - Carrier-Grade NAT (RFC 6598)
// - Unique Local Addresses (IPv6 RFC 4193)
// - Multicast and Broadcast ranges
func NewDefaultBlockedSubnets() *DefaultBlockedSubnets {
	cidrs := []struct {
		cidr   string
		reason string
	}{
		// IPv4 Loopback
		{"127.0.0.0/8", "IPv4 Loopback address"},
		// IPv6 Loopback
		{"::1/128", "IPv6 Loopback address"},
		// AWS IMDS / IPv4 Link-Local (RFC 3927)
		{"169.254.0.0/16", "IPv4 Link-Local / Cloud Instance Metadata (IMDS)"},
		// IPv6 Link-Local (RFC 4291)
		{"fe80::/10", "IPv6 Link-Local address"},
		// RFC 1918 Private Class A
		{"10.0.0.0/8", "RFC 1918 Private Subnet (Class A)"},
		// RFC 1918 Private Class B
		{"172.16.0.0/12", "RFC 1918 Private Subnet (Class B)"},
		// RFC 1918 Private Class C
		{"192.168.0.0/16", "RFC 1918 Private Subnet (Class C)"},
		// Carrier-Grade NAT / Shared Address Space (RFC 6598)
		{"100.64.0.0/10", "Shared Address Space / CGNAT"},
		// IPv6 Unique Local Address (RFC 4193)
		{"fc00::/7", "IPv6 Unique Local Address (ULA)"},
		// Current Network (RFC 1122)
		{"0.0.0.0/8", "Current network ('this' host)"},
		// IPv4 Multicast (RFC 5771)
		{"224.0.0.0/4", "IPv4 Multicast"},
		// IPv6 Multicast (RFC 4291)
		{"ff00::/8", "IPv6 Multicast"},
		// IPv4 Broadcast
		{"255.255.255.255/32", "IPv4 Broadcast"},
		// Documentation / Test networks
		{"192.0.2.0/24", "TEST-NET-1"},
		{"198.51.100.0/24", "TEST-NET-2"},
		{"203.0.113.0/24", "TEST-NET-3"},
		{"198.18.0.0/15", "Network benchmark test subnet"},
	}

	subnets := &DefaultBlockedSubnets{
		blockedNets: make([]*net.IPNet, 0, len(cidrs)),
		reasons:     make([]string, 0, len(cidrs)),
	}

	for _, entry := range cidrs {
		_, ipNet, err := net.ParseCIDR(entry.cidr)
		if err == nil {
			subnets.blockedNets = append(subnets.blockedNets, ipNet)
			subnets.reasons = append(subnets.reasons, entry.reason)
		}
	}

	return subnets
}

// IsBlocked checks if an IP belongs to any blocked subnet.
// Automatically unmasks IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254).
func (b *DefaultBlockedSubnets) IsBlocked(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "nil IP address"
	}

	// Canonicalize IPv4-mapped IPv6 addresses to standard 4-byte IPv4 representation
	canonicalIP := ip
	if ipv4 := ip.To4(); ipv4 != nil {
		canonicalIP = ipv4
	}

	for i, netBlock := range b.blockedNets {
		if netBlock.Contains(canonicalIP) {
			return true, b.reasons[i]
		}
	}

	return false, ""
}

// ErrSSRFDetected indicates an attempted SSRF or access to a prohibited subnet.
type ErrSSRFDetected struct {
	Target string
	IP     string
	Reason string
}

func (e *ErrSSRFDetected) Error() string {
	return fmt.Sprintf("SSRF blocked: target '%s' resolves to prohibited IP %s (%s)", e.Target, e.IP, e.Reason)
}

// ValidateTargetURL parses and checks if a target URL's host is directly an invalid IP.
func ValidateTargetURL(rawURL string, subnets BlockedSubnets) (*url.URL, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("empty upstream URL")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("malformed URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "sse" {
		return nil, fmt.Errorf("unsupported upstream scheme '%s': only http, https, and sse are permitted", parsed.Scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("missing hostname in target URL")
	}

	// Check if host is direct IP literal
	if ip := net.ParseIP(hostname); ip != nil {
		if blocked, reason := subnets.IsBlocked(ip); blocked {
			return nil, &ErrSSRFDetected{Target: rawURL, IP: ip.String(), Reason: reason}
		}
	}

	return parsed, nil
}
