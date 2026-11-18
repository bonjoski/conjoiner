package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
	"github.com/bonjoski/conjoiner/pkg/gateway"
	"github.com/bonjoski/conjoiner/pkg/mandate"
	"github.com/bonjoski/conjoiner/pkg/mcp"
	"github.com/bonjoski/conjoiner/pkg/mcp/guard"
	"github.com/bonjoski/conjoiner/pkg/token"
	"github.com/bonjoski/conjoiner/pkg/version"
)

// RootKeyStorage stores or simulates local broker signing key.
type RootKeyStorage struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func getOrGenerateBrokerKeys() (*RootKeyStorage, error) {
	// 1. Check environment variable
	privBase64 := os.Getenv("CONJOINER_ROOT_KEY")
	if privBase64 != "" {
		privBytes, err := base64.StdEncoding.DecodeString(privBase64)
		if err != nil {
			return nil, fmt.Errorf("failed decoding CONJOINER_ROOT_KEY: %w", err)
		}
		if len(privBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid CONJOINER_ROOT_KEY length %d", len(privBytes))
		}
		priv := ed25519.PrivateKey(privBytes)
		pub := priv.Public().(ed25519.PublicKey)
		return &RootKeyStorage{PrivateKey: priv, PublicKey: pub}, nil
	}

	// 2. Check local user directory ~/.conjoiner/broker.key
	home, err := os.UserHomeDir()
	if err == nil {
		dir := home + "/.conjoiner"
		keyPath := dir + "/broker.key"
		if data, err := os.ReadFile(keyPath); err == nil && len(data) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(data)
			pub := priv.Public().(ed25519.PublicKey)
			return &RootKeyStorage{PrivateKey: priv, PublicKey: pub}, nil
		}

		// Generate and persist with strict 0600 permissions
		pub, priv, err := ed25519.GenerateKey(nil)
		if err == nil {
			if err := os.MkdirAll(dir, 0700); err == nil {
				if err := os.WriteFile(keyPath, priv, 0600); err == nil {
					return &RootKeyStorage{PrivateKey: priv, PublicKey: pub}, nil
				}
			}
		}
	}

	// 3. Fallback: Generate ephemeral in-memory broker key
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed generating fallback broker key: %w", err)
	}
	return &RootKeyStorage{PrivateKey: priv, PublicKey: pub}, nil
}

func getRevocationsFilePath() string {
	if p := os.Getenv("CONJOINER_REVOCATIONS_FILE"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".conjoiner", "revocations.json")
	}
	return ""
}

func initRevocations() {
	if path := getRevocationsFilePath(); path != "" {
		_ = token.LoadRevocationsFromFile(token.DefaultRevocationStore, path)
	}
}

func main() {
	initRevocations()

	exeName := filepath.Base(os.Args[0])
	if exeName == "mcp-conjoiner-proxy" {
		handleMCPShimCommand(os.Args[1:])
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "token":
		handleTokenCommand(os.Args[2:])
	case "dpop":
		handleDPoPCommand(os.Args[2:])
	case "gate":
		handleGateCommand(os.Args[2:])
	case "run", "exec":
		handleGateCommand(append([]string{"exec"}, os.Args[2:]...))
	case "mandate":
		handleMandateCommand(os.Args[2:])
	case "mcp":
		handleMCPCommand(os.Args[2:])
	case "mcp-shim", "mcp-proxy":
		handleMCPShimCommand(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("conjoiner version %s (Go NIST Agentic IAM Broker)\n", version.Version)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Conjoiner: Sovereign Agentic IAM Broker & Policy Gateway

Usage:
  conjoiner <command> [subcommand] [flags]
  mcp-conjoiner-proxy [--require-hardware-presence] [--workflow-manifest <path>] [--audit-log <path>] [--scrub-secrets] -- <target-command> [args...]

Commands:
  run       Run a command deterministically through the policy gate (alias for gate exec)
  token     Manage, issue, attenuate, verify, and revoke task tokens
              issue     --scope <scopes> [--ttl <duration>] [--sub <agent-id>]
              attenuate --parent <jwt> --requested-scope <scopes> [--ttl <duration>]
              verify    --token <jwt>
              revoke    --jti <id> [--reason <reason>] [--ttl <duration>]
  dpop      Manage ephemeral DPoP keypairs and proofs
              keygen    Generate an ephemeral Ed25519 DPoP keypair
  gate      Deterministic policy gateway execution
              exec      --token <jwt> --dpop <proof> --tool <tool> --action <action> [--workflow-manifest <path>] [-- <args...>]
  mandate   Compile natural language security mandates into capability scopes
              compile   [--ai] [--ceiling <scopes>] [--json] <instruction>
  mcp       MCP security tools: audit manifests for SSRF/poisoned upstreams
              audit     --manifest <path> [--purge] [--dry-run] [--json]
              shim      Transparent MCP transport shim & DPoP tool gateway
  mcp-shim  Transparent MCP transport shim & DPoP tool gateway
              --require-hardware-presence  Enforce zero-background-authority hardware presence gate
              --workflow-manifest <path>   Path to workflow manifest JSON for scope attenuation
              --audit-log <path>           Path to append-only forensic audit log file
              --scrub-secrets              Enable Shield secret finding scrubbing on outbound tool output (default: true)
              --token <jwt>                Signed Conjoiner TaskToken JWT
              --scope <scopes>             Comma-separated allowed scopes
  version   Display Conjoiner version`)
}

// Token CLI subcommands
func handleTokenCommand(args []string) {
	if len(args) < 1 {
		fmt.Println(`Usage: conjoiner token <issue|attenuate|verify|revoke> [flags]`)
		os.Exit(1)
	}

	switch args[0] {
	case "issue":
		issueCmd := flag.NewFlagSet("token issue", flag.ExitOnError)
		scopeFlag := issueCmd.String("scope", "", "Comma-separated or space-separated scope capabilities")
		ttlFlag := issueCmd.Duration("ttl", 30*time.Second, "Token TTL (default: 30s)")
		subFlag := issueCmd.String("sub", "agent-root", "Subject / Agent ID")

		if err := issueCmd.Parse(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "flag parse error: %v\n", err)
			os.Exit(1)
		}

		if *scopeFlag == "" {
			fmt.Fprintln(os.Stderr, "Error: --scope is required")
			os.Exit(1)
		}

		keys, err := getOrGenerateBrokerKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		broker, err := token.NewTokenBroker(token.BrokerConfig{
			PrivateKey: keys.PrivateKey,
			PublicKey:  keys.PublicKey,
			DefaultTTL: *ttlFlag,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		dpopKey, err := token.GenerateDPoPKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating DPoP key: %v\n", err)
			os.Exit(1)
		}

		scopes := splitScopes(*scopeFlag)
		ctx := context.Background()
		tok, signedToken, err := broker.IssueRootToken(ctx, token.RootTokenRequest{
			Subject:        *subFlag,
			Scopes:         scopes,
			TTL:            *ttlFlag,
			DPoPThumbprint: dpopKey.Thumbprint(),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error issuing token: %v\n", err)
			os.Exit(1)
		}

		output := map[string]any{
			"access_token": signedToken,
			"token_type":   "DPoP",
			"expires_in":   tok.ExpiresAt - tok.IssuedAt,
			"scope":        tok.Scope,
			"cnf":          tok.CNF,
			"dpop_key": map[string]string{
				"thumbprint": dpopKey.Thumbprint(),
				"jwk_x":      dpopKey.JWK().X,
				"priv":       base64.RawURLEncoding.EncodeToString(dpopKey.PrivateKey),
			},
		}

		enc, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(enc))

	case "attenuate":
		attenuateCmd := flag.NewFlagSet("token attenuate", flag.ExitOnError)
		parentFlag := attenuateCmd.String("parent", "", "Parent token JWT or JSON object containing access_token")
		parentDPoPFlag := attenuateCmd.String("parent-dpop", "", "Parent DPoP proof JWT (optional if --parent JSON includes dpop_key.priv)")
		reqScopeFlag := attenuateCmd.String("requested-scope", "", "Requested attenuated scopes (must be subset)")
		ttlFlag := attenuateCmd.Duration("ttl", 30*time.Second, "Child token TTL")

		if err := attenuateCmd.Parse(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "flag parse error: %v\n", err)
			os.Exit(1)
		}

		if *parentFlag == "" || *reqScopeFlag == "" {
			fmt.Fprintln(os.Stderr, "Error: --parent and --requested-scope are required")
			os.Exit(1)
		}

		exchangeURI := token.DefaultExchangeURI

		// Extract parent token string (may be raw JWT or JSON object)
		parentJWT := *parentFlag
		parentProof := *parentDPoPFlag
		if strings.HasPrefix(strings.TrimSpace(parentJWT), "{") {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(parentJWT), &parsed); err == nil {
				if tok, ok := parsed["access_token"].(string); ok {
					parentJWT = tok
				}
				if parentProof == "" {
					if dkMap, ok := parsed["dpop_key"].(map[string]any); ok {
						if privB64, ok := dkMap["priv"].(string); ok && privB64 != "" {
							if privBytes, decErr := base64.RawURLEncoding.DecodeString(privB64); decErr == nil && len(privBytes) == ed25519.PrivateKeySize {
								parentKey := &token.DPoPKey{
									PrivateKey: ed25519.PrivateKey(privBytes),
									PublicKey:  ed25519.PrivateKey(privBytes).Public().(ed25519.PublicKey),
								}
								if p, pErr := parentKey.CreateProof("POST", exchangeURI, parentJWT); pErr == nil {
									parentProof = p
								}
								parentKey.Zeroize()
							}
						}
					}
				}
			}
		}

		keys, err := getOrGenerateBrokerKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		broker, err := token.NewTokenBroker(token.BrokerConfig{
			PrivateKey:  keys.PrivateKey,
			PublicKey:   keys.PublicKey,
			ExchangeURI: exchangeURI,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		childDPoP, err := token.GenerateDPoPKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating child DPoP key: %v\n", err)
			os.Exit(1)
		}

		childProof, err := childDPoP.CreateProof("POST", exchangeURI, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating DPoP proof: %v\n", err)
			os.Exit(1)
		}

		ctx := context.Background()
		resp, childTok, err := broker.ExchangeToken(ctx, token.TokenExchangeRequest{
			GrantType:        token.GrantTypeTokenExchange,
			SubjectToken:     parentJWT,
			SubjectTokenType: token.TokenTypeAccessToken,
			Scope:            splitScopes(*reqScopeFlag),
			TTL:              *ttlFlag,
			DPoPProof:        childProof,
			ParentDPoPProof:  parentProof,
			ExchangeURI:      exchangeURI,
		})
		if err != nil {
			if errors.Is(err, attenuation.ErrSupersetScopeDenied) {
				fmt.Fprintf(os.Stderr, "Error: requested scope violates attenuation invariant (not a strict subset): %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Error: token exchange failed: %v\n", err)
			}
			os.Exit(1)
		}

		out := map[string]any{
			"access_token": resp.AccessToken,
			"token_type":   resp.TokenType,
			"expires_in":   resp.ExpiresIn,
			"scope":        childTok.Scope,
			"cnf":          childTok.CNF,
			"parent_jti":   childTok.ParentTokenID,
			"depth":        childTok.Depth,
		}
		enc, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(enc))

	case "verify":
		verifyCmd := flag.NewFlagSet("token verify", flag.ExitOnError)
		tokFlag := verifyCmd.String("token", "", "Token JWT string to verify")
		if err := verifyCmd.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if *tokFlag == "" {
			fmt.Fprintln(os.Stderr, "Error: --token is required")
			os.Exit(1)
		}

		keys, err := getOrGenerateBrokerKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		tok, err := token.ParseAndVerifyToken(*tokFlag, keys.PublicKey, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Token Verification Failed: %v\n", err)
			os.Exit(1)
		}

		enc, _ := json.MarshalIndent(tok, "", "  ")
		fmt.Println("Token is VALID:")
		fmt.Println(string(enc))

	case "revoke":
		revokeCmd := flag.NewFlagSet("token revoke", flag.ExitOnError)
		jtiFlag := revokeCmd.String("jti", "", "JTI of the token to revoke")
		reasonFlag := revokeCmd.String("reason", "manual CLI revocation", "Reason for token revocation")
		ttlFlag := revokeCmd.Duration("ttl", 24*time.Hour, "Revocation retention window (default: 24h)")

		if err := revokeCmd.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if strings.TrimSpace(*jtiFlag) == "" {
			fmt.Fprintln(os.Stderr, "Usage: conjoiner token revoke --jti <id> [--reason <reason>] [--ttl <duration>]")
			fmt.Fprintln(os.Stderr, "Error: --jti is required")
			os.Exit(1)
		}

		jti := strings.TrimSpace(*jtiFlag)
		expiresAt := time.Now().UTC().Add(*ttlFlag)

		if err := token.DefaultRevocationStore.RevokeWithReason(jti, expiresAt, *reasonFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error revoking token in memory: %v\n", err)
			os.Exit(1)
		}

		if path := getRevocationsFilePath(); path != "" {
			if err := token.PersistRevocationToFile(path, "jti:"+jti, expiresAt, *reasonFlag); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed persisting revocation to disk: %v\n", err)
			}
		}

		output := map[string]any{
			"status":     "revoked",
			"jti":        jti,
			"reason":     *reasonFlag,
			"expires_at": expiresAt.Format(time.RFC3339),
		}
		enc, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(enc))

	default:
		fmt.Fprintf(os.Stderr, "Unknown token subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleDPoPCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: conjoiner dpop keygen")
		os.Exit(1)
	}

	switch args[0] {
	case "keygen":
		key, err := token.GenerateDPoPKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		out := map[string]string{
			"kty":        key.JWK().Kty,
			"crv":        key.JWK().Crv,
			"x":          key.JWK().X,
			"thumbprint": key.Thumbprint(),
		}
		enc, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(enc))
	default:
		fmt.Fprintf(os.Stderr, "Unknown dpop subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleGateCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: conjoiner gate exec --token <jwt> --dpop <proof> --tool <tool> --action <action> [-- <args...>]")
		os.Exit(1)
	}

	switch args[0] {
	case "exec":
		execCmd := flag.NewFlagSet("gate exec", flag.ExitOnError)
		tokFlag := execCmd.String("token", "", "Task token JWT")
		dpopFlag := execCmd.String("dpop", "", "DPoP proof JWT")
		toolFlag := execCmd.String("tool", "", "Tool name (e.g. echo, git)")
		actionFlag := execCmd.String("action", "", "Tool action (e.g. print, status)")
		resFlag := execCmd.String("resource", "", "Target resource")
		manifestFlag := execCmd.String("workflow-manifest", "", "Path to workflow manifest JSON for scope attenuation")

		if err := execCmd.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		remainingArgs := execCmd.Args()

		if *tokFlag == "" || *toolFlag == "" || *actionFlag == "" {
			fmt.Fprintln(os.Stderr, "Usage: conjoiner gate exec --token <jwt> --dpop <proof> --tool <tool> --action <action> [--workflow-manifest <path>] [-- <args...>]")
			fmt.Fprintln(os.Stderr, "Error: --token, --tool, and --action are required")
			os.Exit(1)
		}

		keys, err := getOrGenerateBrokerKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		var workflowManifest *attenuation.WorkflowManifest
		if *manifestFlag != "" {
			var mErr error
			workflowManifest, mErr = attenuation.LoadWorkflowManifest(*manifestFlag)
			if mErr != nil {
				fmt.Fprintf(os.Stderr, "Error loading workflow manifest: %v\n", mErr)
				os.Exit(1)
			}
		}

		safeExec := gateway.NewSafeLocalExecutor(map[string]string{
			"echo": "/bin/echo",
			"git":  "/usr/bin/git",
		}, 10*time.Second)

		gw, err := gateway.NewGateway(gateway.GatewayConfig{
			BrokerPubKey:     keys.PublicKey,
			Executor:         safeExec,
			RevocationStore:  token.DefaultRevocationStore,
			WorkflowManifest: workflowManifest,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing gateway: %v\n", err)
			os.Exit(1)
		}

		ctx := context.Background()
		resp, err := gw.Execute(ctx, gateway.ToolInvocationRequest{
			Token:            *tokFlag,
			DPoPProof:        *dpopFlag,
			ToolName:         *toolFlag,
			Action:           *actionFlag,
			Resource:         *resFlag,
			Arguments:        remainingArgs,
			WorkflowManifest: workflowManifest,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Gateway Rejection: %v\n", err)
			os.Exit(1)
		}

		enc, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(enc))

	default:
		fmt.Fprintf(os.Stderr, "Unknown gate subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func splitScopes(raw string) []string {
	var out []string
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	for _, f := range fields {
		trimmed := strings.TrimSpace(f)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func handleMandateCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: conjoiner mandate compile [--ai] <natural-language-policy>")
		os.Exit(1)
	}

	switch args[0] {
	case "compile":
		handleMandateCompile(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown mandate subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleMandateCompile(args []string) {
	fs := flag.NewFlagSet("conjoiner mandate compile", flag.ExitOnError)
	aiFlag := fs.Bool("ai", false, "Use Shield-protected AI inference to compile instructions into scopes")
	ceilingFlag := fs.String("ceiling", "", "Comma-separated ceiling scopes bounding compiled output")
	jsonFlag := fs.Bool("json", false, "Output compiled capability scopes as JSON")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "Error: missing natural language policy instruction")
		os.Exit(1)
	}
	instruction := strings.Join(rest, " ")

	var (
		res *mandate.Result
		err error
	)
	if strings.TrimSpace(*ceilingFlag) != "" {
		ceilingSet, cErr := attenuation.NewScopeSet(splitScopes(*ceilingFlag)...)
		if cErr != nil {
			fmt.Fprintf(os.Stderr, "conjoiner mandate invalid --ceiling: %v\n", cErr)
			os.Exit(1)
		}
		res, err = mandate.CompileWithCeiling(context.Background(), instruction, *aiFlag, ceilingSet)
	} else {
		res, err = mandate.Compile(context.Background(), instruction, *aiFlag)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "conjoiner mandate compile failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Compiled Capability Scopes (%d):\n", len(res.Scopes))
	for _, s := range res.Scopes {
		fmt.Printf("  - %s\n", s)
	}
	if res.Advisory != "" {
		fmt.Println("\n[Shield Protected AI Advisory]")
		fmt.Println(res.Advisory)
	}
}

// MCP Shim & Proxy CLI subcommands
func handleMCPShimCommand(args []string) {
	shimCmd := flag.NewFlagSet("mcp-shim", flag.ExitOnError)
	scopeFlag := shimCmd.String("scope", "", "Comma-separated allowed scopes (or set CONJOINER_SCOPES)")
	tokenFlag := shimCmd.String("token", "", "Signed Conjoiner TaskToken JWT (or set CONJOINER_TOKEN)")
	noRedactFlag := shimCmd.Bool("no-redact", false, "Disable Shield secret output redaction")
	scrubSecretsFlag := shimCmd.Bool("scrub-secrets", true, "Enable Shield secret finding scrubbing on outbound tool output (default: true)")
	requirePresenceFlag := shimCmd.Bool("require-hardware-presence", false, "Enforce zero-background-authority hardware presence gate")
	manifestFlag := shimCmd.String("workflow-manifest", "", "Path to workflow manifest JSON for scope attenuation")
	enforceManifestFlag := shimCmd.Bool("enforce-workflow-manifest", false, "Fail closed if workflow manifest is missing")
	auditLogFlag := shimCmd.String("audit-log", "", "Path to append-only audit log file")
	targetCmdFlag := shimCmd.String("target-command", "", "Target command to execute (alternative to -- <command>)")
	_ = shimCmd.Bool("stdin", false, "Read JSON-RPC from standard input")

	// Find "--" delimiter separating flags from target command
	var targetArgs []string
	flagArgs := args
	for i, a := range args {
		if a == "--" {
			flagArgs = args[:i]
			if i+1 < len(args) {
				targetArgs = args[i+1:]
			}
			break
		}
	}

	if err := shimCmd.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "flag parse error: %v\n", err)
		os.Exit(1)
	}

	// If targetArgs was not separated by "--", check remaining positional args or --target-command
	if len(targetArgs) == 0 {
		if strings.TrimSpace(*targetCmdFlag) != "" {
			targetArgs = strings.Fields(strings.TrimSpace(*targetCmdFlag))
		} else {
			targetArgs = shimCmd.Args()
		}
	}

	if len(targetArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: conjoiner mcp-shim [flags] -- <target-command> [args...]")
		fmt.Fprintln(os.Stderr, "   or: mcp-conjoiner-proxy [--require-hardware-presence] [--workflow-manifest <path>] [--audit-log <path>] [--scrub-secrets] -- <target-command> [args...]")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fmt.Fprintln(os.Stderr, "  --require-hardware-presence  Enforce zero-background-authority hardware presence gate")
		fmt.Fprintln(os.Stderr, "  --workflow-manifest <path>   Path to workflow manifest JSON for scope attenuation")
		fmt.Fprintln(os.Stderr, "  --audit-log <path>           Path to append-only forensic audit log file")
		fmt.Fprintln(os.Stderr, "  --scrub-secrets              Enable Shield secret finding scrubbing on outbound tool output (default: true)")
		fmt.Fprintln(os.Stderr, "  --token <jwt>                Signed Conjoiner TaskToken JWT")
		fmt.Fprintln(os.Stderr, "  --scope <scopes>             Comma-separated allowed scopes")
		os.Exit(1)
	}

	var allowedScopes []string
	if *scopeFlag != "" {
		allowedScopes = strings.Split(*scopeFlag, ",")
	}

	var brokerPubKey ed25519.PublicKey
	if *tokenFlag != "" || os.Getenv("CONJOINER_TOKEN") != "" {
		if keys, kErr := getOrGenerateBrokerKeys(); kErr == nil {
			brokerPubKey = keys.PublicKey
		}
	}

	cfg := mcp.Config{
		TargetCommand:           targetArgs[0],
		TargetArgs:              targetArgs[1:],
		AllowedScopes:           allowedScopes,
		Token:                   *tokenFlag,
		BrokerPubKey:            brokerPubKey,
		ScrubSecrets:            *scrubSecretsFlag && !*noRedactFlag,
		RequireHardwarePresence: *requirePresenceFlag,
		WorkflowManifestPath:    *manifestFlag,
		EnforceWorkflowManifest: *enforceManifestFlag,
		AuditLogPath:            *auditLogFlag,
		RevocationStore:         token.DefaultRevocationStore,
	}

	shim, err := mcp.NewTransportShim(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize MCP shim: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := shim.Run(ctx, os.Stdin, os.Stdout, os.Stderr); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "MCP shim runtime error: %v\n", err)
		os.Exit(1)
	}
}

func handleMCPCommand(args []string) {
	if len(args) < 1 {
		fmt.Println(`Usage: conjoiner mcp <audit|shim> [flags]`)
		os.Exit(1)
	}

	switch args[0] {
	case "audit":
		auditCmd := flag.NewFlagSet("mcp audit", flag.ExitOnError)
		manifestPath := auditCmd.String("manifest", "", "Path to MCP registry manifest JSON file")
		purge := auditCmd.Bool("purge", false, "Purge detected poisoned or SSRF upstream entries from the manifest")
		dryRun := auditCmd.Bool("dry-run", false, "Simulate purge without writing changes")
		outputJSON := auditCmd.Bool("json", false, "Emit audit results as JSON")
		auditCmd.Parse(args[1:])

		if *manifestPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --manifest <path> is required")
			os.Exit(1)
		}

		auditor := guard.NewRegistryAuditor(nil, nil)
		ctx := context.Background()

		report, err := auditor.AuditManifest(ctx, *manifestPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
			os.Exit(1)
		}

		if *purge {
			result, err := auditor.PurgePoisonedEntries(ctx, *manifestPath, *dryRun)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Purge failed: %v\n", err)
				os.Exit(1)
			}
			if *outputJSON {
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))
			} else {
				fmt.Printf("Purge complete for %s (dry-run: %v)\n", result.ManifestPath, result.DryRun)
				fmt.Printf("Purged entries: %d\n", result.PurgedCount)
				if result.BackupPath != "" {
					fmt.Printf("Backup saved to: %s\n", result.BackupPath)
				}
			}
			return
		}

		if *outputJSON {
			out, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(out))
		} else {
			fmt.Printf("MCP Registry Manifest Audit: %s\n", report.ManifestPath)
			fmt.Printf("Total Servers:    %d\n", report.TotalServers)
			fmt.Printf("Valid Servers:    %d\n", report.ValidServers)
			fmt.Printf("Poisoned Servers: %d\n", report.PoisonedServers)
			if len(report.PoisonedEntries) > 0 {
				fmt.Println("\nPoisoned / SSRF-Vulnerable Upstreams:")
				for _, entry := range report.PoisonedEntries {
					ipInfo := ""
					if entry.IP != "" {
						ipInfo = fmt.Sprintf(" [%s]", entry.IP)
					}
					fmt.Printf("  - %s: %s%s (%s)\n", entry.ServerKey, entry.URL, ipInfo, entry.Reason)
				}
				os.Exit(2)
			} else {
				fmt.Println("\nManifest is clean: zero SSRF or metadata upstreams detected.")
			}
		}
	case "shim":
		handleMCPShimCommand(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown mcp subcommand: %s\n", args[0])
		os.Exit(1)
	}
}
