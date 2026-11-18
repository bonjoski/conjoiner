# Conjoiner Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, invariants, protocols, and security models governing [`bonjoski/conjoiner`](https://github.com/bonjoski/conjoiner).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-sovereign-agentpass-attenuated-delegation.md)** | **Sovereign AgentPass & Monotonic Scope Attenuation** | `Accepted` | 2026-11-18 | `pkg/agentpass`, `cmd/conjoiner` |
| **[ADR-0002](0002-nist-agentic-iam-broker-dpop-binding.md)** | **NIST SP 800-207A Agentic IAM Broker & RFC 9449 DPoP Binding** | `Accepted` | 2026-10-30 | `pkg/token`, `pkg/mandate` |
| **[ADR-0003](0003-transparent-mcp-transport-shim.md)** | **Transparent MCP Transport Shim & Workload Presence Gate** | `Accepted` | 2026-11-05 | `pkg/mcp`, `mcp-conjoiner-proxy` |

---

## Architectural Principles

1. **Zero Standing Credentials:** Autonomous agents operate with zero persistent credentials; secrets are issued as short-lived, task-bound session tokens tied to an accountable human supervisor.
2. **RFC 9449 DPoP Binding:** Every issued token is cryptographically bound to an agent-generated Ed25519 keypair (`cnf.jkt == proof.jwk.thumbprint`), neutralizing bearer token theft and replay attacks.
3. **Monotonic Scope Attenuation:** Subagent delegation strictly enforces $\text{ChildScope} = \text{ParentScope} \cap \text{RequestedScope}$. Superset permission expansion is mathematically impossible.
4. **Deterministic Policy Gateway:** Separates probabilistic prompt reasoning from tool execution, ensuring tool arguments and state changes pass deterministic validation before execution.
