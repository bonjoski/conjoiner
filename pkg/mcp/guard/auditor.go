package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PoisonedServerEntry records an entry identified as SSRF-vulnerable or poisoned.
type PoisonedServerEntry struct {
	ServerKey string `json:"server_key"`
	URL       string `json:"url"`
	Reason    string `json:"reason"`
	IP        string `json:"ip,omitempty"`
}

// AuditReport details findings from inspecting an MCP registry manifest.
type AuditReport struct {
	ManifestPath    string                `json:"manifest_path"`
	TotalServers    int                   `json:"total_servers"`
	ValidServers    int                   `json:"valid_servers"`
	PoisonedServers int                   `json:"poisoned_servers"`
	PoisonedEntries []PoisonedServerEntry `json:"poisoned_entries"`
	AuditDuration   time.Duration         `json:"audit_duration"`
}

// PurgeResult summarizes the modification of an MCP registry manifest.
type PurgeResult struct {
	ManifestPath string `json:"manifest_path"`
	BackupPath   string `json:"backup_path,omitempty"`
	PurgedCount  int    `json:"purged_count"`
	DryRun       bool   `json:"dry_run"`
}

// RegistryAuditor inspects and cleans MCP registry configurations.
type RegistryAuditor struct {
	Subnets  BlockedSubnets
	Resolver Resolver
	Timeout  time.Duration
}

// NewRegistryAuditor creates an initialized RegistryAuditor.
func NewRegistryAuditor(subnets BlockedSubnets, resolver Resolver) *RegistryAuditor {
	if subnets == nil {
		subnets = NewDefaultBlockedSubnets()
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &RegistryAuditor{
		Subnets:  subnets,
		Resolver: resolver,
		Timeout:  5 * time.Second,
	}
}

// AuditManifest inspects a manifest file and returns a structured audit report.
func (a *RegistryAuditor) AuditManifest(ctx context.Context, manifestPath string) (*AuditReport, error) {
	start := time.Now()
	cleanPath := filepath.Clean(manifestPath)

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading manifest at '%s': %w", cleanPath, err)
	}

	report := &AuditReport{
		ManifestPath:    cleanPath,
		PoisonedEntries: make([]PoisonedServerEntry, 0),
	}

	// Try parsing generic JSON
	var rawRoot map[string]interface{}
	if err := json.Unmarshal(data, &rawRoot); err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}

	urlsToCheck := a.extractUpstreamURLs(rawRoot)
	report.TotalServers = len(urlsToCheck)

	for key, rawURL := range urlsToCheck {
		if rawURL == "" {
			continue
		}

		poisoned, reason, ip := a.isUpstreamPoisoned(ctx, rawURL)
		if poisoned {
			report.PoisonedServers++
			report.PoisonedEntries = append(report.PoisonedEntries, PoisonedServerEntry{
				ServerKey: key,
				URL:       rawURL,
				Reason:    reason,
				IP:        ip,
			})
		} else {
			report.ValidServers++
		}
	}

	report.AuditDuration = time.Since(start)
	return report, nil
}

// PurgePoisonedEntries removes all detected poisoned entries and persists the cleaned manifest.
func (a *RegistryAuditor) PurgePoisonedEntries(ctx context.Context, manifestPath string, dryRun bool) (*PurgeResult, error) {
	cleanPath := filepath.Clean(manifestPath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading manifest: %w", err)
	}

	var rawRoot map[string]interface{}
	if err := json.Unmarshal(data, &rawRoot); err != nil {
		return nil, fmt.Errorf("invalid manifest JSON: %w", err)
	}

	urlsToCheck := a.extractUpstreamURLs(rawRoot)
	keysToPurge := make(map[string]bool)

	for key, rawURL := range urlsToCheck {
		if rawURL == "" {
			continue
		}
		if poisoned, _, _ := a.isUpstreamPoisoned(ctx, rawURL); poisoned {
			keysToPurge[key] = true
		}
	}

	result := &PurgeResult{
		ManifestPath: cleanPath,
		PurgedCount:  len(keysToPurge),
		DryRun:       dryRun,
	}

	if len(keysToPurge) == 0 || dryRun {
		return result, nil
	}

	// Create backup before mutation
	backupPath := fmt.Sprintf("%s.bak.%d", cleanPath, time.Now().UnixNano())
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed creating manifest backup: %w", err)
	}
	result.BackupPath = backupPath

	// Mutate and remove keys
	a.removeKeysFromRoot(rawRoot, keysToPurge)

	cleanData, err := json.MarshalIndent(rawRoot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed re-marshaling cleaned manifest: %w", err)
	}

	if err := os.WriteFile(cleanPath, append(cleanData, '\n'), 0644); err != nil {
		return nil, fmt.Errorf("failed writing cleaned manifest: %w", err)
	}

	return result, nil
}

func (a *RegistryAuditor) isUpstreamPoisoned(ctx context.Context, rawURL string) (bool, string, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true, "Malformed URL", ""
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return true, "Missing hostname", ""
	}

	// 1. Direct IP check
	if ip := net.ParseIP(hostname); ip != nil {
		if blocked, reason := a.Subnets.IsBlocked(ip); blocked {
			return true, reason, ip.String()
		}
		return false, "", ip.String()
	}

	// 2. DNS resolution check with timeout
	resolveCtx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()

	ips, err := a.Resolver.LookupIP(resolveCtx, "ip", hostname)
	if err != nil {
		return false, fmt.Sprintf("DNS lookup unresolvable (%v)", err), ""
	}

	for _, ip := range ips {
		if blocked, reason := a.Subnets.IsBlocked(ip); blocked {
			return true, fmt.Sprintf("%s via DNS resolution", reason), ip.String()
		}
	}

	return false, "", ""
}

func (a *RegistryAuditor) extractUpstreamURLs(root map[string]interface{}) map[string]string {
	results := make(map[string]string)

	// Format 1: "mcpServers": { "name": { "url": "..." } }
	if serversRaw, ok := root["mcpServers"]; ok {
		if serverMap, ok := serversRaw.(map[string]interface{}); ok {
			for key, val := range serverMap {
				if conf, ok := val.(map[string]interface{}); ok {
					for _, urlField := range []string{"url", "endpoint", "upstream_url", "upstream"} {
						if u, ok := conf[urlField].(string); ok && u != "" {
							results["mcpServers."+key] = u
							break
						}
					}
				}
			}
		}
	}

	// Format 2: "servers": [ { "id": "...", "upstream_url": "..." } ]
	if serversRaw, ok := root["servers"]; ok {
		if serverList, ok := serversRaw.([]interface{}); ok {
			for idx, item := range serverList {
				if conf, ok := item.(map[string]interface{}); ok {
					key := fmt.Sprintf("servers[%d]", idx)
					if idVal, ok := conf["id"].(string); ok && idVal != "" {
						key = fmt.Sprintf("servers[%s]", idVal)
					}
					for _, urlField := range []string{"upstream_url", "url", "endpoint", "target"} {
						if u, ok := conf[urlField].(string); ok && u != "" {
							results[key] = u
							break
						}
					}
				}
			}
		}
	}

	return results
}

func (a *RegistryAuditor) removeKeysFromRoot(root map[string]interface{}, keysToPurge map[string]bool) {
	// Clean mcpServers
	if serversRaw, ok := root["mcpServers"]; ok {
		if serverMap, ok := serversRaw.(map[string]interface{}); ok {
			for fullKey := range keysToPurge {
				if strings.HasPrefix(fullKey, "mcpServers.") {
					shortKey := strings.TrimPrefix(fullKey, "mcpServers.")
					delete(serverMap, shortKey)
				}
			}
		}
	}

	// Clean servers list
	if serversRaw, ok := root["servers"]; ok {
		if serverList, ok := serversRaw.([]interface{}); ok {
			filtered := make([]interface{}, 0, len(serverList))
			for idx, item := range serverList {
				if conf, ok := item.(map[string]interface{}); ok {
					keyIndex := fmt.Sprintf("servers[%d]", idx)
					keyID := ""
					if idVal, ok := conf["id"].(string); ok {
						keyID = fmt.Sprintf("servers[%s]", idVal)
					}
					if !keysToPurge[keyIndex] && (keyID == "" || !keysToPurge[keyID]) {
						filtered = append(filtered, item)
					}
				}
			}
			root["servers"] = filtered
		}
	}
}
