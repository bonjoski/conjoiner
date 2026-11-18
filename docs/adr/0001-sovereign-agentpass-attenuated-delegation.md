# ADR-0001: Sovereign AgentPass & Monotonic Scope Attenuation

- **Status:** Accepted
- **Date:** 2026-11-18
- **Component:** `pkg/agentpass`, `cmd/conjoiner`
- **Deciders:** Identity Architect & Policy Gateway Engineer

---

## 1. Context & Problem Statement

Autonomous coding agents (Cursor, Claude Code, OpenCode) and their subagents face an "agentic identity crisis":
1. **Unaccountable Machine Operations:** Agents execute state-mutating actions (git pushes, cloud provisioning, database updates) using long-lived personal access tokens (PATs) or static environment variables. If credentials leak or an agent misbehaves, tracing actions to an accountable human supervisor is difficult, and revocation requires rotating global keys.
2. **Subagent Privilege Expansion:** When a parent agent delegates a slice of work to a subagent, existing platforms lack mathematical scope boundaries; subagents can request broader scopes than the delegating parent.
3. **The "Hop Tax" & Biometric Fatigue:** Centralized commercial gateways introduce multi-second cloud hops and mobile push notifications for approvals, breaking multi-agent concurrency ($N=8$ parallel subagents in distinct git worktrees) and stalling developer loops.

---

## 2. Decision Drivers

- **Zero Standing Credentials:** Agents start with zero ambient credentials. Credentials reside in local hardware vaults and are issued as 30-second single-use tool tokens on demand.
- **Human Accountability:** Every agent capability pass must be explicitly bound to a named human supervisor.
- **Mathematical Attenuation:** Strict lattice subsetting: $\text{ChildScope} = \text{ParentScope} \cap \text{RequestedScope}$.
- **Sub-5ms Hop Tax SLA:** Zero remote cloud gateway hops; local Unix domain socket IPC and in-memory cryptographic verification.
- **$N=8$ Concurrency:** Subagents must run concurrently without biometric prompt storms or UI deadlocks.

---

## 3. Decision Outcome

We implemented **Sovereign AgentPass** in `conjoiner`:

### 3.1 Architecture Overview

```mermaid
flowchart TD
    subgraph HumanSupervisor ["🧑‍💻 Human Supervisor"]
        Dev["Developer (Session Sponsor)"]
    end

    subgraph ConjoinerCore ["⚖️ Conjoiner AgentPass Engine"]
        RootPass["Root AgentPass<br/>(Bound to Human Supervisor & Root Scope)"]
        Attenuator["Attenuating Delegation Engine<br/>ChildScope = Parent ∩ Requested"]
        ChildPass["Attenuated Child Pass<br/>(Depth d+1, Strictly Subsetted)"]
        HardwareGate["Hardware Presence & Amortized Lease Cache<br/>(5m TTL, 72ns lookup)"]
        TokenMinter["Tool Token Minter<br/>(30s DPoP-Bound TaskToken)"]
    end

    subgraph ExecutionPlane ["🌐 Deterministic Execution"]
        Gateway["Conjoiner Policy Gateway"]
        TargetTool["Target Tool API / CLI<br/>(git, aws, mcp)"]
    end

    Dev -->|1. Issue Root Pass| RootPass
    RootPass -->|2. Subagent Delegation| Attenuator
    Attenuator -->|3. Issue Attenuated Pass| ChildPass
    ChildPass -->|4. Tool Call Request| HardwareGate
    HardwareGate -->|5. Amortized Fast-Path Check| TokenMinter
    TokenMinter -->|6. Mint 30s DPoP Token| Gateway
    Gateway -->|7. Execute Tool Atomically| TargetTool
```

### 3.2 Key Invariants

1. **Human Supervisor Binding:** Every `AgentPass` contains an explicit `human_supervisor` claim. An un-supervised agent pass fails verification (`ErrUnauthorizedSupervisor`).
2. **Monotonic Scope Attenuation:** When delegating to a child subagent:
   $$\text{Scope}_{\text{child}} = \text{Scope}_{\text{parent}} \cap \text{Scope}_{\text{requested}}$$
   If any requested scope is not covered by the parent pass, issuance strictly rejects with `ErrSupersetScopeDenied`.
3. **Bounded Delegation Depth:** Each delegation increments `delegation_depth` by 1. If depth exceeds `max_depth` (default: 3), delegation is rejected (`ErrMaxDelegationDepthExceeded`), preventing cyclic privilege chains.
4. **Amortized Hardware Leasing:** High-risk actions query `HardwareGate`. The first high-risk action in a session evaluates Locksmith presence/Touch ID and caches a 5-minute session lease. Sibling subagents execute under the active lease non-interactively (**72.92 ns/op**).
5. **30-Second DPoP Tool Tokens:** Tool execution tokens expire monotonically after 30 seconds and are bound to an agent's ephemeral Ed25519 DPoP keypair (`cnf.jkt`).

---

## 4. Performance & Benchmark Metrics

Benchmarked on Apple Silicon (M3 Max, Go 1.27):

| Operation | Latency | Throughput | Target SLA | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Tool Token Minting** | **16.3 µs (0.016 ms)** | ~68,400 ops/sec | < 5.0 ms | **PASS (300x faster)** |
| **Amortized Lease Lookup** | **72.9 ns (0.00007 ms)** | ~16,590,000 ops/sec | < 0.1 ms | **PASS** |
| **End-to-End Gateway Exec** | **3.18 ms** | Full round-trip | < 10.0 ms | **PASS** |

---

## 5. STRIDE Security Analysis

| Threat Category | Concrete Attack Vector | Mitigation / Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Rogue subagent replaying stolen parent token. | Rejected: Token requires valid Ed25519 DPoP proof matching `cnf.jkt`. |
| **Tampering** | Modifying AgentPass payload to elevate scope. | Invalidates EdDSA signature signed by broker key; rejected. |
| **Repudiation** | Subagent executing state mutation and denying origin. | Audit ledger links execution receipt hash, JTI, and parent session. |
| **Information Disclosure** | Scraping access token string from memory. | Token string is useless without private DPoP key in RAM; expires in 30s. |
| **Denial of Service** | $N=8$ parallel subagents prompt-bombing Touch ID. | Amortized session leasing caches biometric elevation for 5m. |
| **Elevation of Privilege** | Subagent requesting broader scope than parent. | Attenuation engine rejects any non-subset scope. |
