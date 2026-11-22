# Use Case 04: `UB-MCP-v1` Structured Denials & `BLPR-v1` SIR Lineage

> **Goal:** Gate local MCP servers through `conjoiner`'s `mcp-conjoiner-proxy` so every tool call receives RFC 9449 DPoP + monotonic scope enforcement, returns 1-turn `UB-MCP-v1` self-correction payloads on denial, and links Conjoiner's `SignedIntentReceipt` (SIR) into downstream `BLPR-v1` provenance receipts.

## Workflow
1. **Wire MCP servers through Conjoiner automatically:**
   ```bash
   fabrial init --mcp --conjoiner-wrap --apply
   ```
2. **Start a local session so `FABRIAL_SESSION_ID` & `FABRIAL_RECEIPT_DIR` are exported:**
   ```bash
   eval "$(fabrial session begin)"
   ```
3. **What `mcp-conjoiner-proxy` Enforces on Every Tool Call:**
   * Verifies RFC 9449 DPoP proof, monotonic scope attenuation, workspace path containment, and taint gates.
   * Records a hash-chained `SignedIntentReceipt` (`pkg/ledger`) and propagates both `FABRIAL_SESSION_ID` and `CONJOINER_SIR_ID` (`rcpt_...`) into the child MCP process env and JSON-RPC `_meta`.
   * On any denial (`DENY_SCOPE` / `DENY_DRIFT`), returns a `UB-MCP-v1` `CallToolResult` (`isError: true`, calm ≤3-line ANSI-sanitized text, and `structuredContent` with `exit_code: 10` and `receipt_id`).
