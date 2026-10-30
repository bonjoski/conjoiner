# Conjoiner (`bonjoski/conjoiner`)

> **Sovereign Agentic IAM Broker & Policy Gateway**  
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

---

## Running Tests

```bash
go test -v ./...
```
