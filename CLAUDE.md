# Claude Code Guidelines for `conjoiner`

> **Authoritative Ecosystem Runbook:** [`spanreed/docs/knowledge-base/07-conjoiner.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/07-conjoiner.md)

## Build & Test Commands
- **Build Binary:** `go build -o bin/conjoiner ./cmd/conjoiner`
- **Unit Tests:** `go test -v ./...`
- **Linter:** `golangci-lint run`
- **Issue Token:** `./bin/conjoiner issue --subject "agent" --scope "repo:read" --ttl 30s`
- **Attenuate:** `./bin/conjoiner attenuate --parent-token <jwt> --requested-scope "repo:read"`

## Code Style & Architectural Invariants
- NIST SP 800-207A Non-Human Identity (NHI) compliance.
- RFC 9449 Ed25519 DPoP proof binding (`cnf.jkt`).
- Strict 30-second ephemeral TTL (60s maximum hard ceiling).
- Monotonic scope attenuation: $ChildScope = ParentScope \cap RequestedScope$.
- Deterministic policy gateway: execute tools directly so agents never see downstream credentials.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
