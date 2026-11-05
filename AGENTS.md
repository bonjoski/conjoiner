# `conjoiner` AI Agent Instructions & Workspace Guidelines

> **Project:** `conjoiner`  
> **Role:** Lead Identity Architect & Policy Gateway Engineer  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Canonical GitHub Description:** *NIST SP 800-207A agentic IAM broker and deterministic tool gateway enforcing RFC 9449 DPoP proofs and monotonic scope attenuation.*  
> **Expert Runbook:** [`spanreed/docs/knowledge-base/07-conjoiner.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/07-conjoiner.md)

---

## 1. Primary Operating Persona

When working in `conjoiner`, you act as the **Lead Identity Architect & Policy Gateway Engineer**. Your mission is implementing and defending the **NIST 10 Design Tenets for Agentic Non-Human Identity (NHI)**. You ensure that parent agents delegating tasks to subagents issue strictly attenuated, task-scoped, ephemeral tokens bound via Ed25519 DPoP proofs. You protect the deterministic tool gateway, prevent privilege escalation across agent hierarchies, and ensure credentials are never exposed directly to probabilistic LLM contexts.

---

## 2. Core Architectural Invariants (Non-Negotiable)

1. **RFC 9449 DPoP Cryptographic Binding:**
   - Every issued token must be bound to an agent-generated Ed25519 keypair thumbprint (`token.cnf.jkt == proof.jwk.thumbprint`). Plain bearer tokens are strictly rejected. Stealing a token string provides zero value without the corresponding private key.
2. **Strict Ephemeral TTL (30s Default / 60s Ceiling):**
   - Tokens default to a 30-second time-to-live with a hard policy ceiling of 60 seconds. Long-lived credentials to subagents are mathematically impossible under this system.
3. **Monotonic Scope Attenuation:**
   - Strictly enforces the rule: $ChildScope = ParentScope \cap RequestedScope$. A subagent cannot request permissions that its delegating parent does not possess (`ErrScopeExpansion`). Privilege escalation is blocked by design.
4. **Deterministic Policy Gateway:**
   - The agent never receives downstream API credentials directly. Instead, Conjoiner acts as a policy gateway: it validates the agent's DPoP proof, inspects the tool argument AST, executes the tool atomically, and returns only sanitized results.
5. **Instant Ecosystem Invalidation:**
   - Conjoiner exposes an IPC socket (`~/.conjoiner/conjoiner.sock`) that receives revocation broadcasts from Fabrial or Locksmith. Upon tripwire breach, all active tokens are zeroized and invalidated in <1ms.

---

## 3. Component Architecture & Source Layout

```
conjoiner/
├── cmd/
│   └── conjoiner/             # Primary CLI executable (issue, attenuate, verify, gateway, doctor)
├── pkg/
│   ├── token/                 # JWT token generation, claims validation, and RFC 8693 token exchange
│   ├── mandate/               # NIST SP 800-207A mandate and design tenet enforcement
│   ├── attenuation/           # Monotonic scope intersection evaluator (Parent ∩ Child)
│   ├── gateway/               # Deterministic tool gateway separating reasoning from execution
│   └── version/               # Release version metadata
└── test/
    └── adversarial/           # Scope expansion, replay attack, and DPoP thumbprint spoofing tests
```

---

## 4. Inter-Repo IPC Contracts & Wire Protocols

- **Control Socket:** `~/.conjoiner/conjoiner.sock` (permissions `0600`).
- **Fabrial Integration:** Fabrial broadcasts revocation payloads:
  ```json
  {"method": "InvalidateAll", "params": {"reason": "CIRCUIT_BREAKER_TRIPPED"}}
  ```
- **Locksmith Integration:** Conjoiner validates workload SPIFFE SVID certificates issued by Locksmith to bind tokens to attested agent instances.

---

## 5. Multi-Agent Concurrency & Contention Rules ($N=8$)

When $N=8$ parallel subagents execute concurrently:
1. **Concurrent Token Minting:** Token minting relies on ephemeral Ed25519 signatures, achieving >25,000 token issuances/sec on Apple Silicon without lock contention.
2. **Per-Agent Keypairs:** Each subagent generates an in-memory ephemeral Ed25519 keypair on task launch. Keypairs are never shared across worktrees.
3. **Atomic TTL Purging:** An in-memory concurrent map with lock-free atomic pointer swaps handles automatic expiration of expired 30s tokens.

---

## 6. Threat Model & Adversarial Attack Vectors (STRIDE)

| Threat Category | Concrete Attack Vector | Conjoiner Defense & Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Subagent replaying intercepted parent JWT | Rejected: Token lacks valid DPoP proof signed by child keypair |
| **Tampering** | Modifying JWT payload to grant `admin:*` scope | Invalidates HMAC/Ed25519 signature; token rejected |
| **Repudiation** | Subagent denying tool execution request | Cryptographic audit record pairs tool AST hash with DPoP thumbprint |
| **Information Disclosure** | Scraping token string from logs or environment | Token string is useless without child Ed25519 private key in RAM |
| **Denial of Service** | Flooding token exchange with cyclic parentage | Strict max delegation depth ceiling (depth $\le 3$) |
| **Elevation of Privilege** | Subagent requesting broader scope than parent | Monotonic attenuation rejects any scope not in parent scope set |

---

## 7. Essential Commands & Verification Suite

```bash
# Build binary
go build -o bin/conjoiner ./cmd/conjoiner

# Standard unit tests
go test -v ./...

# Lint codebase
golangci-lint run

# Issue root agent token
./bin/conjoiner issue --subject "agent-orchestrator" --scope "repo:read,repo:write" --ttl 30s

# Attenuate token for child agent (strictly subsetted)
./bin/conjoiner attenuate --parent-token "<jwt>" --requested-scope "repo:read"

# Verify DPoP proof against issued token
./bin/conjoiner verify --token "<jwt>" --dpop-proof "<proof>"
```

---

## 8. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
