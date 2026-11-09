package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
	"github.com/bonjoski/conjoiner/pkg/token"
)

const (
	// DefaultMaxMessageSize bounds MCP JSON-RPC line frames to 4 MiB by default.
	DefaultMaxMessageSize int64 = 4 * 1024 * 1024
)

var (
	// ErrMissingTargetCommand indicates no command was specified to run.
	ErrMissingTargetCommand = errors.New("missing target command to execute")
	// ErrMissingAuthorization indicates neither explicit AllowedScopes nor a valid Token was configured.
	ErrMissingAuthorization = errors.New("missing authorization: explicit AllowedScopes or verified Token is required")
	// ErrInvalidShimToken indicates the configured MCP task token failed cryptographic verification.
	ErrInvalidShimToken = errors.New("invalid or unverified MCP task token")
)

var sensitiveEnvPrefixes = []string{
	"CONJOINER_",
	"AWS_",
	"AZURE_",
	"GOOGLE_",
	"GCP_",
	"GITHUB_",
	"GH_",
	"GITLAB_",
	"OPENAI_",
	"ANTHROPIC_",
	"GEMINI_",
	"SLACK_",
	"STRIPE_",
	"NPM_",
	"PYPI_",
	"DOCKER_",
	"KUBE",
	"VAULT_",
	"SSH_",
	"GPG_",
	"LD_",
	"DYLD_",
	"DATABASE_",
	"PGPASSWORD",
	"MYSQL_",
	"REDIS_",
	"MONGO",
}

var sensitiveEnvSubstrings = []string{
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"PRIVATE_KEY",
	"API_KEY",
	"APIKEY",
	"CREDENTIAL",
}

// SanitizeChildEnv strips broker signing keys, cloud credentials, and dynamic linker variables
// before spawning a downstream MCP child process. Always returns a non-nil slice so exec.Cmd
// never falls back to inheriting os.Environ().
func SanitizeChildEnv(environ []string) []string {
	clean := make([]string, 0, len(environ))
	for _, entry := range environ {
		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		keyUpper := strings.ToUpper(entry[:eq])
		blocked := false
		for _, prefix := range sensitiveEnvPrefixes {
			if strings.HasPrefix(keyUpper, prefix) {
				blocked = true
				break
			}
		}
		if !blocked {
			for _, sub := range sensitiveEnvSubstrings {
				if strings.Contains(keyUpper, sub) {
					blocked = true
					break
				}
			}
		}
		if !blocked {
			clean = append(clean, entry)
		}
	}
	return clean
}

// Config configures the transparent MCP transport shim.
type Config struct {
	TargetCommand  string
	TargetArgs     []string
	AllowedScopes  []string
	Token          string
	BrokerPubKey   ed25519.PublicKey
	MaxMessageSize int64
	ScrubSecrets   bool
}

// TransportShim coordinates bidirectional streaming JSON-RPC inspection.
type TransportShim struct {
	cfg           Config
	scopeSet      attenuation.ScopeSet
	verifiedToken *token.TaskToken
	sanitizer     *Sanitizer
	pendingMu     sync.Mutex
	pending       map[string]string // maps request ID string to method name
}

func resolveAmbientBrokerPubKey() ed25519.PublicKey {
	if pubB64 := strings.TrimSpace(os.Getenv("CONJOINER_BROKER_PUBKEY")); pubB64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(pubB64); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw)
		}
	}
	if privB64 := strings.TrimSpace(os.Getenv("CONJOINER_ROOT_KEY")); privB64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(privB64); err == nil && len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw).Public().(ed25519.PublicKey)
		}
	}
	return nil
}

func filterNonEmptyScopes(in []string) []string {
	var out []string
	for _, s := range in {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// NewTransportShim constructs a verified MCP transport shim.
func NewTransportShim(cfg Config) (*TransportShim, error) {
	if strings.TrimSpace(cfg.TargetCommand) == "" {
		return nil, ErrMissingTargetCommand
	}
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = DefaultMaxMessageSize
	}

	rawScopes := filterNonEmptyScopes(cfg.AllowedScopes)
	if len(rawScopes) == 0 {
		if envScopes := strings.TrimSpace(os.Getenv("CONJOINER_SCOPES")); envScopes != "" {
			rawScopes = filterNonEmptyScopes(strings.Split(envScopes, ","))
		}
	}

	tokStr := strings.TrimSpace(cfg.Token)
	if tokStr == "" && len(rawScopes) == 0 {
		tokStr = strings.TrimSpace(os.Getenv("CONJOINER_TOKEN"))
	}

	var (
		scopeSet      attenuation.ScopeSet
		verifiedToken *token.TaskToken
	)

	if tokStr != "" {
		pubKey := cfg.BrokerPubKey
		if len(pubKey) != ed25519.PublicKeySize {
			pubKey = resolveAmbientBrokerPubKey()
		}
		if len(pubKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: broker public key is required to verify token", ErrInvalidShimToken)
		}

		parsedTok, err := token.ParseAndVerifyToken(tokStr, pubKey, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidShimToken, err)
		}
		tokScopes, err := parsedTok.ScopeSet()
		if err != nil || tokScopes.IsEmpty() {
			return nil, fmt.Errorf("%w: token contains no valid capability scopes", ErrInvalidShimToken)
		}
		verifiedToken = parsedTok

		if len(rawScopes) > 0 {
			explicitSet, err := attenuation.NewScopeSet(rawScopes...)
			if err != nil {
				return nil, fmt.Errorf("invalid explicit scopes: %w", err)
			}
			scopeSet = attenuation.Intersect(tokScopes, explicitSet)
			if scopeSet.IsEmpty() {
				return nil, fmt.Errorf("%w: explicit scopes have empty intersection with token scopes", ErrMissingAuthorization)
			}
		} else {
			scopeSet = tokScopes
		}
	} else {
		// CNJ-03: Never default to allow-all wildcard "*" when neither AllowedScopes nor Token is configured
		if len(rawScopes) == 0 {
			return nil, ErrMissingAuthorization
		}
		var err error
		scopeSet, err = attenuation.NewScopeSet(rawScopes...)
		if err != nil {
			return nil, fmt.Errorf("invalid scopes: %w", err)
		}
		if scopeSet.IsEmpty() {
			return nil, ErrMissingAuthorization
		}
	}

	return &TransportShim{
		cfg:           cfg,
		scopeSet:      scopeSet,
		verifiedToken: verifiedToken,
		sanitizer:     NewSanitizer(),
		pending:       make(map[string]string),
	}, nil
}

// Run executes the target command subprocess and transparently pipes stdin/stdout through security filters.
func (s *TransportShim) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, clientErr io.Writer) error {
	cmd := exec.CommandContext(ctx, s.cfg.TargetCommand, s.cfg.TargetArgs...)
	cmd.Env = SanitizeChildEnv(os.Environ())

	childStdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to open child stdin pipe: %w", err)
	}
	defer childStdin.Close()

	childStdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to open child stdout pipe: %w", err)
	}

	childStderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to open child stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start target command '%s': %w", s.cfg.TargetCommand, err)
	}

	// Forward stderr directly with zero buffering
	go func() {
		if clientErr != nil {
			_, _ = io.Copy(clientErr, childStderr)
		}
	}()

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// Goroutine 1: Client -> Server (Inbound tools/call and tools/list interception)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer childStdin.Close()
		if err := s.pipeClientToServer(clientIn, childStdin, clientOut); err != nil && !errors.Is(err, io.EOF) {
			errChan <- err
		}
	}()

	// Goroutine 2: Server -> Client (Outbound tools/list filtering and Shield secret scrubbing)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.pipeServerToClient(childStdout, clientOut); err != nil && !errors.Is(err, io.EOF) {
			errChan <- err
		}
	}()

	wg.Wait()

	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()

	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

// readBoundedLine reads up to maxBytes until '\n' or EOF without unbounded heap growth.
// If a line exceeds maxBytes, remaining bytes up to '\n' or EOF are drained in fixed chunks and tooLong=true is returned.
func readBoundedLine(r *bufio.Reader, maxBytes int64) ([]byte, bool, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxMessageSize
	}

	var acc []byte
	for {
		frag, err := r.ReadSlice('\n')
		if int64(len(acc))+int64(len(frag)) > maxBytes {
			// Drain remainder of the oversized line in fixed chunks without allocating
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, true, err
			}
			return nil, true, err
		}

		acc = append(acc, frag...)
		if err == nil {
			return acc, false, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return acc, false, err
	}
}

func writeJSONRPCError(w io.Writer, id json.RawMessage, code int, message string) {
	if w == nil {
		return
	}
	errResp := NewErrorResponse(id, code, message)
	respBytes, err := json.Marshal(errResp)
	if err != nil {
		return
	}
	respBytes = append(respBytes, '\n')
	_, _ = w.Write(respBytes)
}

// pipeClientToServer processes inbound JSON-RPC messages from client IDE to MCP server.
func (s *TransportShim) pipeClientToServer(r io.Reader, serverIn io.Writer, clientOut io.Writer) error {
	reader := bufio.NewReaderSize(r, 64*1024)

	for {
		line, tooLong, err := readBoundedLine(reader, s.cfg.MaxMessageSize)
		if tooLong {
			writeJSONRPCError(clientOut, nil, ErrCodeInvalidRequest,
				fmt.Sprintf("Conjoiner policy blocked oversized MCP frame (> %d bytes)", s.cfg.MaxMessageSize))
			if err != nil {
				return err
			}
			continue
		}

		if len(line) > 0 {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				if shouldForward := s.handleInboundLine(trimmed, serverIn, clientOut); !shouldForward {
					continue
				}
				if _, wErr := serverIn.Write(line); wErr != nil {
					return wErr
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

// hasDuplicateJSONKeys detects duplicate keys in any JSON object within data to prevent parser-differential smuggling.
func hasDuplicateJSONKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		isObj      bool
		expectKey  bool
		seenFields map[string]bool
	}
	var stack []frame

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}

		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.isObj && top.expectKey {
				if delim, ok := tok.(json.Delim); ok && delim == '}' {
					stack = stack[:len(stack)-1]
					if len(stack) > 0 && stack[len(stack)-1].isObj {
						stack[len(stack)-1].expectKey = true
					}
					continue
				}
				keyStr, ok := tok.(string)
				if !ok {
					return true
				}
				if top.seenFields[keyStr] {
					return true
				}
				top.seenFields[keyStr] = true
				top.expectKey = false
				continue
			}
		}

		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, frame{
					isObj:      true,
					expectKey:  true,
					seenFields: make(map[string]bool),
				})
			case '[':
				stack = append(stack, frame{isObj: false})
			case ']', '}':
				if len(stack) == 0 {
					return true
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].isObj {
					stack[len(stack)-1].expectKey = true
				}
			}
			continue
		}

		// Scalar value completed inside an object
		if len(stack) > 0 && stack[len(stack)-1].isObj {
			stack[len(stack)-1].expectKey = true
		}
	}
}

// handleInboundLine checks permissions and prompt injection on inbound client messages.
// Fails closed (returns false and writes JSON-RPC error) on batch arrays, malformed JSON, or policy violations.
func (s *TransportShim) handleInboundLine(line []byte, _ io.Writer, clientOut io.Writer) bool {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return false
	}

	// CNJ-03: Explicitly reject JSON-RPC batch arrays `[...]` (fail closed)
	if trimmed[0] == '[' {
		writeJSONRPCError(clientOut, nil, ErrCodeInvalidRequest, "Conjoiner policy rejected JSON-RPC batch array: single-request framing required")
		return false
	}
	if trimmed[0] != '{' {
		writeJSONRPCError(clientOut, nil, ErrCodeParseError, "Conjoiner policy rejected non-object JSON-RPC frame")
		return false
	}

	if hasDuplicateJSONKeys(trimmed) {
		writeJSONRPCError(clientOut, nil, ErrCodeInvalidRequest, "Conjoiner policy rejected JSON-RPC frame with duplicate object keys")
		return false
	}

	var msg JSONRPCMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		writeJSONRPCError(clientOut, nil, ErrCodeParseError, "Conjoiner policy rejected malformed JSON-RPC message")
		return false
	}

	if msg.JSONRPC != "" && msg.JSONRPC != "2.0" {
		writeJSONRPCError(clientOut, msg.ID, ErrCodeInvalidRequest, "Unsupported JSON-RPC version")
		return false
	}

	// Enforce live token TTL when configured with a verified TaskToken
	if s.verifiedToken != nil && s.verifiedToken.IsExpired(time.Now().UTC()) {
		writeJSONRPCError(clientOut, msg.ID, ErrCodeTokenExpired, "Conjoiner task token has expired")
		return false
	}

	idStr := string(msg.ID)
	if idStr != "" && msg.Method != "" {
		s.pendingMu.Lock()
		s.pending[idStr] = msg.Method
		s.pendingMu.Unlock()
	}

	if strings.HasPrefix(msg.Method, "tools/") && msg.Method != "tools/list" && msg.Method != "tools/call" {
		writeJSONRPCError(clientOut, msg.ID, ErrCodeMethodNotFound, fmt.Sprintf("Unsupported MCP tools method: %s", msg.Method))
		return false
	}

	if msg.Method == "tools/call" {
		paramsTrim := bytes.TrimSpace(msg.Params)
		if len(paramsTrim) == 0 || paramsTrim[0] != '{' {
			writeJSONRPCError(clientOut, msg.ID, ErrCodeInvalidParams, "Malformed or missing tools/call params object")
			return false
		}

		var params ToolCallParams
		if err := json.Unmarshal(paramsTrim, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			writeJSONRPCError(clientOut, msg.ID, ErrCodeInvalidParams, "Invalid tools/call parameters: tool name is required")
			return false
		}

		// 1. Semantic firewall: check tool name and arguments (raw + decoded JSON strings) for prompt injection
		if injected, reason := DetectPromptInjection(params.Name); injected {
			writeJSONRPCError(clientOut, msg.ID, ErrCodePromptInjectionDetected, fmt.Sprintf("Conjoiner policy blocked tool call: %s", reason))
			return false
		}
		if len(params.Arguments) > 0 {
			if injected, reason := DetectJSONPromptInjection(params.Arguments); injected {
				writeJSONRPCError(clientOut, msg.ID, ErrCodePromptInjectionDetected, fmt.Sprintf("Conjoiner policy blocked tool call: %s", reason))
				return false
			}
		}

		// 2. Monotonic scope attenuation check (fail closed on parse errors!)
		toolScope := fmt.Sprintf("tool:exec:%s", params.Name)
		reqScope, err := attenuation.ParseScope(toolScope)
		if err != nil || !s.scopeSet.Contains(reqScope) {
			writeJSONRPCError(clientOut, msg.ID, ErrCodeScopeDenied,
				fmt.Sprintf("Monotonic scope attenuation denied tool invocation: %s (required: %s)", params.Name, toolScope))
			return false
		}
	}

	return true
}

// pipeServerToClient processes outbound responses from MCP server to client IDE.
func (s *TransportShim) pipeServerToClient(r io.Reader, clientOut io.Writer) error {
	reader := bufio.NewReaderSize(r, 64*1024)

	for {
		line, tooLong, err := readBoundedLine(reader, s.cfg.MaxMessageSize)
		if tooLong {
			writeJSONRPCError(clientOut, nil, ErrCodeInternalError,
				fmt.Sprintf("Conjoiner blocked oversized downstream MCP response (> %d bytes)", s.cfg.MaxMessageSize))
			if err != nil {
				return err
			}
			continue
		}

		if len(line) > 0 {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				transformed := s.handleOutboundLine(trimmed)
				if _, wErr := clientOut.Write(transformed); wErr != nil {
					return wErr
				}
				if !bytes.HasSuffix(transformed, []byte("\n")) {
					if _, wErr := clientOut.Write([]byte("\n")); wErr != nil {
						return wErr
					}
				}
			} else {
				if _, wErr := clientOut.Write(line); wErr != nil {
					return wErr
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

// handleOutboundLine filters tool listings and scrubs credentials from responses.
func (s *TransportShim) handleOutboundLine(line []byte) []byte {
	var msg JSONRPCMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		if s.cfg.ScrubSecrets && s.sanitizer != nil {
			if scrubbed, modified := s.sanitizer.ScrubSecrets(line); modified {
				return scrubbed
			}
		}
		return line
	}

	idStr := string(msg.ID)
	var method string
	if idStr != "" {
		s.pendingMu.Lock()
		method = s.pending[idStr]
		delete(s.pending, idStr)
		s.pendingMu.Unlock()
	}

	// 1. If response to tools/list, filter out unauthorized tools
	if method == "tools/list" && len(msg.Result) > 0 {
		var toolResult ToolListResult
		if err := json.Unmarshal(msg.Result, &toolResult); err == nil {
			filtered := make([]ToolDef, 0, len(toolResult.Tools))
			for _, t := range toolResult.Tools {
				tScope, err := attenuation.ParseScope(fmt.Sprintf("tool:exec:%s", t.Name))
				if err == nil && s.scopeSet.Contains(tScope) {
					filtered = append(filtered, t)
				}
			}
			toolResult.Tools = filtered
			if newResultBytes, err := json.Marshal(toolResult); err == nil {
				msg.Result = newResultBytes
				if newMsgBytes, err := json.Marshal(msg); err == nil {
					line = newMsgBytes
				}
			}
		}
	}

	// 2. Secret Redaction on tool outputs
	if s.cfg.ScrubSecrets && s.sanitizer != nil {
		scrubbed, modified := s.sanitizer.ScrubSecrets(line)
		if modified {
			return scrubbed
		}
	}

	return line
}
