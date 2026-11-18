# ADR-0003: Transparent MCP Transport Shim & Workload Presence Gate

- **Status:** Accepted
- **Date:** 2026-11-05
- **Component:** `pkg/mcp`, `mcp-conjoiner-proxy`
- **Deciders:** Identity Architect & Policy Gateway Engineer

---

## 1. Context & Problem Statement

Model Context Protocol (MCP) clients (Cursor, Claude Desktop, Antigravity) interact with upstream MCP servers over JSON-RPC 2.0 (stdio or SSE).
1. Existing MCP clients execute tool calls directly without cryptographic presence checks or scope attenuation.
2. Rogue background processes or unattended agents can invoke connected tools (GitHub, Slack, AWS) while developer workstations are locked or unattended.
3. Unredacted API tokens or secrets can leak into LLM conversation logs from scanner output.

---

## 2. Decision Outcome

We created `mcp-conjoiner-proxy`, an inline, transparent streaming transport shim for MCP:

1. **Hardware Presence Gate (`--require-hardware-presence`):**
   - Intercepts all incoming `tools/call` JSON-RPC messages.
   - Evaluates developer workstation presence (macOS console user active / display unlocked) via Locksmith daemon before permitting execution.
   - Unattended background calls fail closed immediately (`-32001 Policy Violation`).
2. **Workflow Manifest Scope Attenuation (`--workflow-manifest`):**
   - Restricts tool calls to scopes explicitly declared in a workflow manifest. Mutating endpoints (e.g. `merge_request:merge`) are blocked unless declared.
3. **Outbound Secret Scrubbing (`--scrub-secrets`):**
   - Intercepts outbound tool responses, replacing high-entropy API tokens, private keys, and credentials with `[REDACTED_SECRET]` before they enter LLM context.
4. **Sub-Minute OpenTelemetry Tracing:**
   - Injects an immutable `X-Correlation-JTI` into execution metadata for end-to-end audit tracing.

---

## 3. Consequences

- **Positive:** Zero background authority; unattended data exfiltration attempts fail closed; secrets are sanitized prior to prompt context ingestion.
- **Negative:** Streaming JSON inspection adds ~1.2ms latency overhead per tool call.
