# Conjoiner (`bonjoski/conjoiner`)

[![CI](https://github.com/bonjoski/conjoiner/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/conjoiner/actions/workflows/ci.yml)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> [!NOTE]
> **Developer Tooling & Safe Harbor Scope**: Conjoiner is strictly an unmanaged local CLI utility and Go reference implementation of IETF RFC 9449 (DPoP) and NIST SP 800-207A tenets for personal developer agent workflows. It does not provide enterprise Identity Provider (IdP) services, centralized IAM, or fleet-wide policy servers.

> **Deterministic Tool Gateway & RFC 9449 DPoP Token Reference Implementation**  
> Implementing the NIST 10 Design Tenets for Agentic Non-Human Identity (NHI)

---

## Overview

`Conjoiner` is an inline cryptographic broker and deterministic authorization gateway that bridges probabilistic AI agent reasoning (Cursor, Claude Code, LangChain, MCP) with deterministic tool execution.

### Key Capabilities:
- **IETF RFC 8693 Token Exchange:** Exchanges parent agent identity for short-lived, task-bound child tokens.
- **IETF RFC 9449 DPoP (Demonstrating Proof-of-Possession):** Binds ephemeral tokens to agent-generated Ed25519 keypairs, neutralizing bearer token theft and replay attacks.
- **Ephemeral Lifespans (NIST Tenet #3):** Strict default 30-second TTL (configurable up to 60-second policy ceiling).
- **Cryptographic Scope Attenuation (NIST Tenet #4):** Enforces `ChildScope = ParentScope ∩ RequestedScope` via monotonic delegation chains. Denies any superset permission expansion.
- **Deterministic Policy Gateway (NIST Tenet #8):** Separates probabilistic prompt reasoning from tool execution. The agent never receives downstream credentials; Conjoiner evaluates deterministic AST/allowlists and executes tools atomically.

---

## Architecture & Data Flow

```
Parent Agent (Probabilistic)
      │
      ▼ (Request Task Token)
Conjoiner Broker ──► Signs Ephemeral DPoP Token (30s TTL, Ed25519)
      │
      ▼ (Sub-Agent Delegation)
Attenuating Scope Engine ──► Validates ChildScope ⊆ ParentScope
      │
      ▼ (Tool Invocation Request with DPoP Proof)
Deterministic Policy Gateway
      ├── Validates DPoP Binding (token.cnf.jkt == proof.jwk.thumbprint)
      ├── Checks Replay Cache (JTI replay denial)
      ├── Verifies Scope & Argument Sanitization (no shell injection)
      └── Executes Tool Directly (Zero TOCTOU / Zero Credential Exposure)
```

---

## Directory Layout

```
.
├── cmd/
│   └── conjoiner/          # CLI entrypoint (token issue/attenuate/verify, gate exec)
├── pkg/
│   ├── attenuation/        # Scope parsing, subset validation, delegation envelopes
│   ├── gateway/            # Deterministic policy gateway & tool executors
│   └── token/              # RFC 8693 Token Exchange, RFC 9449 DPoP & replay cache
├── go.mod
└── README.md
```

---

## CLI Usage

### 1. Issue Ephemeral Root Token (30s TTL)
```bash
TOKEN_JSON=$(conjoiner token issue --scope "fs:read:/tmp/workspace,tool:exec:git:status" --ttl 30s)
```

### 2. Attenuate Scope for Sub-Agent (Valid Subset)
```bash
conjoiner token attenuate --parent "$TOKEN_JSON" --requested-scope "fs:read:/tmp/workspace/src"
```

### 3. Privilege Escalation Attempt (Superset Denied)
```bash
conjoiner token attenuate --parent "$TOKEN_JSON" --requested-scope "fs:write:/etc"
# Exits with Code 1:
# Error: requested scope violates attenuation invariant (not a strict subset): superset permission expansion denied
```

### 4. Sovereign AgentPass (Accountable Human-Supervised Agent Sessions)

Conjoiner provides an open-standard, zero-standing-privilege counterweight to proprietary commercial platforms (e.g. HYPR AgentPass), delivering local developer workstation governance without cloud lock-in or mobile push latency:

```bash
# 1. Issue an AgentPass tied to a named human supervisor and initial scope
PASS_JSON=$(conjoiner agentpass issue \
  --supervisor "developer@bonjo.dev" \
  --agent "agent:cursor:main" \
  --scope "repo:read,git:status,git:commit" \
  --ttl 1h \
  --json)

# 2. Attenuate pass for a child subagent (enforces ChildScope = ParentScope ∩ RequestedScope)
CHILD_PASS=$(conjoiner agentpass attenuate \
  --parent "$PASS_JSON" \
  --child-agent "agent:cursor:sub-01" \
  --requested-scope "repo:read,git:commit" \
  --json)

# 3. Mint short-lived, single-use 30s tool execution token on demand
conjoiner agentpass mint-token \
  --pass "$CHILD_PASS" \
  --action "git:commit"
```

---

## 💡 Core Use Cases & Recipes

Every primary developer use case is backed by dedicated, copy-pasteable recipes in [**`docs/use-cases/`**](docs/use-cases/README.md):

| Use Case | Scenario & Quick Recipe | Full Guide |
| :--- | :--- | :--- |
| **Ephemeral DPoP Delegation** | Issue 30s TTL Ed25519-bound capability tokens to subagents:<br/>`conjoiner token issue --subagent worker-1 --ttl 30s` | [Guide](docs/use-cases/01-ephemeral-dpop-delegation.md) |
| **Path-Restricted Attenuation** | Monotonically restrict subagent write capabilities to a subfolder:<br/>`conjoiner token attenuate --token "$PARENT" --restrict-path "./src/components"` | [Guide](docs/use-cases/02-path-restricted-attenuation.md) |
| **Cryptographic Intent Ledger** | Maintain and verify an immutable Merkle audit trail of all subagent actions:<br/>`conjoiner audit --verify` | [Guide](docs/use-cases/03-cryptographic-intent-ledger.md) |
| **MCP Repo-Confinement & Inode Pinning** | Prevent traversal & symlink escapes in tool calls (`write_file`/`edit_file`):<br/>`conjoiner gate confinement --root "$PWD" --path "$TARGET"` | [RFC-42](https://github.com/bonjoski/spanreed/blob/main/docs/plans/accepted/2026-11-19-mcp-repo-confinement-and-keystore-frame-integrity-rfc.md) |

### Securing Model Context Protocol (MCP) Tool Calls with Inode Confinement

To protect against agentic path traversal and symlink escapes (mitigating `GHSA-w42c-h7hr-f67p`), Conjoiner provides the `containment.StrictPathValidator` asserting that all requested tool call file paths strictly resolve within the canonical repository root:

```go
import "github.com/bonjoski/conjoiner/pkg/containment"

validator := containment.NewStrictPathValidator()
canonicalPath, err := validator.ValidatePath(workspaceRoot, requestedPath)
if err != nil {
    // Fails closed on dot-dot escapes, out-of-bounds symlinks, or parent directory races
    return nil, fmt.Errorf("tool call rejected by repo confinement: %w", err)
}
```

---

## SLSA Provenance & Verification

Conjoiner complies with the **SLSA v1.0** specification.

Verify provenance with GitHub CLI:
```bash
gh attestation verify conjoiner --repo bonjoski/conjoiner
```

Or verify offline using Soulcaster:
```bash
soulcaster verify --attestation conjoiner.intoto.jsonl bin/conjoiner
```

---

## Running Tests

```bash
go test -v ./...
```
