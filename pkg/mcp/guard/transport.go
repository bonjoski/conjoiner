package guard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	ErrInsecureScheme   = errors.New("insecure HTTP scheme prohibited: TLS required")
	ErrNoResolvableIP   = errors.New("hostname did not resolve to any IP address")
	ErrInvalidTransport = errors.New("invalid or uninitialized transport")
)

// Resolver defines the DNS lookup interface.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Option configures EgressGuardTransport.
type Option func(*EgressGuardTransport)

// WithBlockedSubnets overrides or customizes the blocked subnets filter.
func WithBlockedSubnets(b BlockedSubnets) Option {
	return func(t *EgressGuardTransport) {
		t.BlockedRanges = b
	}
}

// WithEnforceTLSOnly mandates that all target URLs use HTTPS.
func WithEnforceTLSOnly(enforce bool) Option {
	return func(t *EgressGuardTransport) {
		t.EnforceTLSOnly = enforce
	}
}

// WithCustomResolver injects a custom DNS resolver (useful for testing DNS rebinding).
func WithCustomResolver(r Resolver) Option {
	return func(t *EgressGuardTransport) {
		t.Resolver = r
	}
}

// WithTimeout sets dial and request timeouts.
func WithTimeout(d time.Duration) Option {
	return func(t *EgressGuardTransport) {
		t.Timeout = d
	}
}

// EgressGuardTransport implements http.RoundTripper with strict SSRF and DNS Rebinding protections.
type EgressGuardTransport struct {
	Dialer         *net.Dialer
	Resolver       Resolver
	BlockedRanges  BlockedSubnets
	EnforceTLSOnly bool
	Timeout        time.Duration
	TLSClientConfig *tls.Config
}

// NewEgressGuardTransport constructs an initialized EgressGuardTransport.
func NewEgressGuardTransport(opts ...Option) *EgressGuardTransport {
	t := &EgressGuardTransport{
		Dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		Resolver:        net.DefaultResolver,
		BlockedRanges:   NewDefaultBlockedSubnets(),
		EnforceTLSOnly:  false,
		Timeout:         15 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	for _, opt := range opts {
		opt(t)
	}

	return t
}

// RoundTrip resolves the target host, validates candidate IPs against blocked subnets,
// and pins the connection to the validated IP to defeat DNS Rebinding TOCTOU race conditions.
func (t *EgressGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("nil HTTP request or URL")
	}

	targetURL := req.URL
	scheme := strings.ToLower(targetURL.Scheme)

	if t.EnforceTLSOnly && scheme != "https" {
		return nil, ErrInsecureScheme
	}

	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme '%s'", scheme)
	}

	hostname := targetURL.Hostname()
	if hostname == "" {
		return nil, errors.New("missing hostname in request URL")
	}

	ctx := req.Context()
	if t.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.Timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	var targetIPs []net.IP

	// Check if the hostname is already an IP literal
	if ip := net.ParseIP(hostname); ip != nil {
		targetIPs = []net.IP{ip}
	} else {
		// Resolve hostname using the configured resolver
		ips, err := t.Resolver.LookupIP(ctx, "ip", hostname)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for '%s': %w", hostname, err)
		}
		targetIPs = ips
	}

	if len(targetIPs) == 0 {
		return nil, ErrNoResolvableIP
	}

	// Fail-closed invariant: ALL resolved candidate IPs must pass the CIDR filter.
	// If any resolved IP points to an internal/metadata address, reject the request entirely.
	for _, ip := range targetIPs {
		if blocked, reason := t.BlockedRanges.IsBlocked(ip); blocked {
			return nil, &ErrSSRFDetected{
				Target: targetURL.String(),
				IP:     ip.String(),
				Reason: reason,
			}
		}
	}

	// Select and pin the first validated IP
	pinnedIP := targetIPs[0]

	// Determine port
	port := targetURL.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Clone TLS config to preserve SNI hostname verification
	tlsConfig := t.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	if tlsConfig.ServerName == "" && net.ParseIP(hostname) == nil {
		tlsConfig.ServerName = hostname
	}

	// Construct an isolated transport that connects strictly to the pinned IP
	pinnedTransport := &http.Transport{
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			targetAddr := net.JoinHostPort(pinnedIP.String(), port)
			return t.Dialer.DialContext(dialCtx, network, targetAddr)
		},
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return pinnedTransport.RoundTrip(req)
}

// NewClient returns an http.Client pre-configured with EgressGuardTransport.
func NewClient(opts ...Option) *http.Client {
	transport := NewEgressGuardTransport(opts...)
	return &http.Client{
		Transport: transport,
		Timeout:   transport.Timeout,
	}
}
