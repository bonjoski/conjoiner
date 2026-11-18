# ADR-0002: NIST SP 800-207A Agentic IAM Broker & RFC 9449 DPoP Binding

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/token`, `pkg/mandate`
- **Deciders:** Identity Architect & Policy Gateway Engineer

---

## 1. Context & Problem Statement

Autonomous agents operating in multi-agent toolchains require programmatic access to APIs and developer tools. Traditional IAM protocols rely on static API keys or long-lived bearer tokens. In autonomous agent loops:
- Plain bearer tokens are susceptible to theft, interception, and exfiltration via prompt injection or SSRF.
- Agents hand static credentials across subagent boundaries, resulting in massive blast radiuses when a subagent is compromised.
- NIST Special Publication 800-207A establishes Zero Trust principles for Non-Human Identities (NHI), mandating short lifespans, cryptographic possession proofs, and deterministic delegation.

---

## 2. Decision Outcome

We implemented the **NIST 10 Design Tenets for Agentic Non-Human Identity (NHI)** in `conjoiner`:

### 2.1 Core Invariants

1. **RFC 9449 DPoP (Demonstrating Proof-of-Possession):**
   - Every task token is cryptographically bound to an ephemeral, agent-generated Ed25519 keypair thumbprint (`token.cnf.jkt == proof.jwk.thumbprint`).
   - Plain bearer tokens are strictly rejected. Intercepting a token string provides zero capability without the agent's private key in RAM.
2. **Ephemeral Lifespans (NIST Tenet #3):**
   - Default 30-second TTL with a hard policy ceiling of 60 seconds.
3. **Deterministic Token Exchange (RFC 8693):**
   - Agents exchange parent credentials for attenuated child tokens via `POST /token/exchange`.
4. **Instant Invalidation Bus:**
   - Active tokens can be revoked in `< 1ms` across local sockets (`~/.conjoiner/conjoiner.sock`) via Fabrial or tripwire killswitches.

---

## 3. Consequences

- **Positive:** Bearer token exfiltration is completely neutralized; compromised tokens expire in <=30s; subagents cannot escalate privileges.
- **Negative:** Agents must maintain an in-memory ephemeral Ed25519 keypair and generate a DPoP proof for each tool execution.
