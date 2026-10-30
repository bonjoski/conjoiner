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
	"strings"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
	"github.com/bonjoski/conjoiner/pkg/gateway"
	"github.com/bonjoski/conjoiner/pkg/mandate"
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

func main() {
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
	case "mandate":
		handleMandateCommand(os.Args[2:])
	case "version":
		fmt.Printf("conjoiner version %s (Go NIST Agentic IAM Broker)\n", version.Version)
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

Commands:
  token    Manage, issue, attenuate, and verify task tokens
  dpop     Manage ephemeral DPoP keypairs and proofs
  gate     Deterministic policy gateway execution
  mandate  Compile natural language security mandates into capability scopes
  version  Display Conjoiner version`)
}

// Token CLI subcommands
func handleTokenCommand(args []string) {
	if len(args) < 1 {
		fmt.Println(`Usage: conjoiner token <issue|attenuate|verify> [flags]`)
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
			},
		}

		enc, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(enc))

	case "attenuate":
		attenuateCmd := flag.NewFlagSet("token attenuate", flag.ExitOnError)
		parentFlag := attenuateCmd.String("parent", "", "Parent token JWT or JSON object containing access_token")
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

		// Extract parent token string (may be raw JWT or JSON object)
		parentJWT := *parentFlag
		if strings.HasPrefix(strings.TrimSpace(parentJWT), "{") {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(parentJWT), &parsed); err == nil {
				if tok, ok := parsed["access_token"].(string); ok {
					parentJWT = tok
				}
			}
		}

		keys, err := getOrGenerateBrokerKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		broker, err := token.NewTokenBroker(token.BrokerConfig{
			PrivateKey: keys.PrivateKey,
			PublicKey:  keys.PublicKey,
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

		exchangeURI := "https://broker.local/token"
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

		if err := execCmd.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		remainingArgs := execCmd.Args()

		if *tokFlag == "" || *toolFlag == "" || *actionFlag == "" {
			fmt.Fprintln(os.Stderr, "Error: --token, --tool, and --action are required")
			os.Exit(1)
		}

		keys, err := getOrGenerateBrokerKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		safeExec := gateway.NewSafeLocalExecutor(map[string]string{
			"echo": "/bin/echo",
			"git":  "/usr/bin/git",
		}, 10*time.Second)

		gw, err := gateway.NewGateway(gateway.GatewayConfig{
			BrokerPubKey: keys.PublicKey,
			Executor:     safeExec,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing gateway: %v\n", err)
			os.Exit(1)
		}

		ctx := context.Background()
		resp, err := gw.Execute(ctx, gateway.ToolInvocationRequest{
			Token:     *tokFlag,
			DPoPProof: *dpopFlag,
			ToolName:  *toolFlag,
			Action:    *actionFlag,
			Resource:  *resFlag,
			Arguments: remainingArgs,
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
	jsonFlag := fs.Bool("json", false, "Output compiled capability scopes as JSON")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "Error: missing natural language policy instruction")
		os.Exit(1)
	}
	instruction := strings.Join(rest, " ")

	res, err := mandate.Compile(context.Background(), instruction, *aiFlag)
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
