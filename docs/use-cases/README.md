# 💡 Conjoiner End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/conjoiner`](https://github.com/bonjoski/conjoiner)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Conjoiner** is a deterministic Non-Human Identity (NHI) capability gateway and agentic IAM broker compliant with NIST SP 800-207A. It provides short-lived Ed25519 DPoP delegation tokens, cryptographically signed intent ledgers, and revocable capability attenuation for autonomous multi-agent swarms.

This directory provides task-oriented recipes for common agent delegation and capability restriction workflows.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Mechanism |
| :--- | :--- | :--- | :--- |
| **[01. Ephemeral DPoP Delegation](01-ephemeral-dpop-delegation.md)** | Issue short-lived (30s TTL) cryptographically bound capability tokens to autonomous subagents. | `conjoiner token issue --subagent <id>` | RFC 9449 Ed25519 DPoP |
| **[02. Path-Restricted Attenuation](02-path-restricted-attenuation.md)** | Attenuate a broad workspace write capability down to a single scoped subdirectory. | `conjoiner token attenuate --token <tok>` | Revocable Attenuation |
| **[03. Cryptographic Intent Ledger](03-cryptographic-intent-ledger.md)** | Maintain and verify an append-only, tamper-evident audit log of all subagent tool invocations. | `conjoiner audit --verify` | Merkle Intent Ledger |
| **[04. In-App AI Blast-Radius Middleware](02-in-app-ai-blast-radius-middleware.md)** | Embed deterministic tool-call/budget ceilings, strict JSON validation, and a 1-flip read-only kill-switch outside the LLM loop (`Go` / `TS` / `Python`). | `pkg/aiboundary` (`BlastRadiusPolicy`) | In-Process Deterministic Guard |
