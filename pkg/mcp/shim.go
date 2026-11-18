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
	TargetCommand           string
	TargetArgs              []string
	AllowedScopes           []string
	Token                   string
	BrokerPubKey            ed25519.PublicKey
	MaxMessageSize          int64
	ScrubSecrets            bool
	EnableTaintGate         bool
	SessionID               string
	TaintGate               TaintGate
	RequireHardwarePresence bool
	PresenceChecker         PresenceChecker
	WorkflowManifest        *attenuation.WorkflowManifest
	WorkflowManifestPath    string
	EnforceWorkflowManifest bool
	AuditLogPath            string
	RevocationStore         token.RevocationStore
	CorrelationJTI          string
}

// TransportShim coordinates bidirectional streaming JSON-RPC inspection.
type TransportShim struct {
	cfg                   Config
	scopeSet              attenuation.ScopeSet
	parentScopeSet        attenuation.ScopeSet
	workflowManifest      *attenuation.WorkflowManifest
	presenceChecker       PresenceChecker
	verifiedToken         *token.TaskToken
	revocationStore       token.RevocationStore
	activeCorrelationJTI  string
	pendingCorrelationJTI map[string]string
	sanitizer             *Sanitizer
	taintGate             TaintGate
	pendingMu             sync.Mutex
	pending               map[string]string // maps request ID string to method name
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

	parentScopeSet := scopeSet

	// Enforce workflow manifest if configured
	if cfg.EnforceWorkflowManifest && cfg.WorkflowManifest == nil && strings.TrimSpace(cfg.WorkflowManifestPath) == "" {
		return nil, attenuation.ErrManifestRequired
	}

	var wm *attenuation.WorkflowManifest
	if cfg.WorkflowManifest != nil {
		wm = cfg.WorkflowManifest
	} else if strings.TrimSpace(cfg.WorkflowManifestPath) != "" {
		loaded, err := attenuation.LoadWorkflowManifest(cfg.WorkflowManifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed loading workflow manifest: %w", err)
		}
		wm = loaded
	}

	if wm != nil {
		effective, err := wm.EffectiveScope(parentScopeSet)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating workflow scope attenuation: %w", err)
		}
		if effective.IsEmpty() {
			return nil, fmt.Errorf("%w: workflow manifest permitted scopes have empty intersection with parent scopes", ErrMissingAuthorization)
		}
		scopeSet = effective
	}

	var tg TaintGate
	if cfg.EnableTaintGate {
		if cfg.TaintGate != nil {
			tg = cfg.TaintGate
		} else {
			tg = NewDefaultTaintGate()
		}
	}

	var presenceChecker PresenceChecker
	if cfg.RequireHardwarePresence {
		if cfg.PresenceChecker != nil {
			presenceChecker = cfg.PresenceChecker
		} else {
			presenceChecker = NewDefaultPresenceChecker()
		}
	}

	revStore := cfg.RevocationStore
	if revStore == nil {
		revStore = token.DefaultRevocationStore
	}

	corrJTI := cfg.CorrelationJTI
	if corrJTI == "" && verifiedToken != nil {
		corrJTI = verifiedToken.JTI
	}

	return &TransportShim{
		cfg:                   cfg,
		scopeSet:              scopeSet,
		parentScopeSet:        parentScopeSet,
		workflowManifest:      wm,
		presenceChecker:       presenceChecker,
		verifiedToken:         verifiedToken,
		revocationStore:       revStore,
		activeCorrelationJTI:  corrJTI,
		pendingCorrelationJTI: make(map[string]string),
		sanitizer:             NewSanitizer(),
		taintGate:             tg,
		pending:               make(map[string]string),
	}, nil
}

// ActiveCorrelationJTI returns the currently tracked correlation JTI.
func (s *TransportShim) ActiveCorrelationJTI() string {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return s.activeCorrelationJTI
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

// HandleInboundLine evaluates and filters an inbound JSON-RPC message.
func (s *TransportShim) HandleInboundLine(line []byte, serverIn io.Writer, clientOut io.Writer) bool {
	return s.handleInboundLine(line, serverIn, clientOut)
}

// HandleOutboundLine inspects, tags trace metadata, and sanitizes an outbound JSON-RPC message.
func (s *TransportShim) HandleOutboundLine(line []byte) []byte {
	return s.handleOutboundLine(line)
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

	// Enforce live token revocation when configured with a verified TaskToken
	if s.verifiedToken != nil && s.revocationStore != nil && s.revocationStore.IsRevoked(s.verifiedToken.JTI, s.verifiedToken.SessionID, s.verifiedToken.Subject) {
		writeJSONRPCError(clientOut, msg.ID, ErrCodePolicyViolation, "Conjoiner task token has been revoked")
		return false
	}

	reqJTI := s.activeCorrelationJTI
	if len(msg.Params) > 0 {
		var metaHolder struct {
			Meta struct {
				JTI            string `json:"jti"`
				CorrelationJTI string `json:"X-Correlation-JTI"`
			} `json:"_meta"`
		}
		if err := json.Unmarshal(msg.Params, &metaHolder); err == nil {
			if metaHolder.Meta.CorrelationJTI != "" {
				reqJTI = metaHolder.Meta.CorrelationJTI
			} else if metaHolder.Meta.JTI != "" {
				reqJTI = metaHolder.Meta.JTI
			}
		}
	}
	if reqJTI != "" {
		s.activeCorrelationJTI = reqJTI
	}

	idStr := string(msg.ID)
	if idStr != "" && msg.Method != "" {
		s.pendingMu.Lock()
		s.pending[idStr] = msg.Method
		if reqJTI != "" {
			s.pendingCorrelationJTI[idStr] = reqJTI
		}
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

		// 0a. Validate Token/Session revocation status on tool dispatch
		if s.revocationStore != nil {
			checkJTI := s.activeCorrelationJTI
			checkSID := s.cfg.SessionID
			checkSub := ""
			if s.verifiedToken != nil {
				checkJTI = s.verifiedToken.JTI
				checkSID = s.verifiedToken.SessionID
				checkSub = s.verifiedToken.Subject
			}
			if s.revocationStore.IsRevoked(checkJTI, checkSID, checkSub) {
				writeJSONRPCError(clientOut, msg.ID, ErrCodePolicyViolation,
					"Conjoiner policy blocked tool call: task token has been revoked")
				return false
			}
		}

		// 0b. Zero-Background-Authority: Hardware Presence Check
		if s.cfg.RequireHardwarePresence {
			checker := s.presenceChecker
			if checker == nil {
				checker = NewDefaultPresenceChecker()
			}
			if err := checker.CheckPresence(context.Background()); err != nil {
				LogPresenceRejection(s.cfg.AuditLogPath, params.Name, s.cfg.SessionID, err)
				writeJSONRPCError(clientOut, msg.ID, ErrCodePolicyViolation,
					"Zero-Background-Authority: User presence failed / locked")
				return false
			}
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

		// 1b. Dynamic Taint Gate: intercept multi-step exfiltration on egress tools
		if s.taintGate != nil && IsEgressToolName(params.Name) {
			sessionID := s.cfg.SessionID
			if sessionID == "" {
				sessionID = "default"
			}
			if allowed, reason := s.taintGate.EvaluateEgress(sessionID, params.Name, params.Arguments); !allowed {
				writeJSONRPCError(clientOut, msg.ID, ErrCodeTaintViolation, fmt.Sprintf("Conjoiner policy blocked egress: %s", reason))
				return false
			}
		}

		// 2. Monotonic scope attenuation check
		candidateScopes := extractToolCandidateScopes(params.Name)

		// 2a. If workflow manifest is configured, check mutating operation gating
		if s.workflowManifest != nil {
			var authErr error
			hasMutating := false
			for _, cand := range candidateScopes {
				if attenuation.IsStateMutating(cand) {
					hasMutating = true
					if err := s.workflowManifest.AuthorizeOperation(s.parentScopeSet, cand); err != nil {
						authErr = err
						break
					}
				}
			}
			if !hasMutating && len(candidateScopes) > 0 {
				authorized := false
				for _, cand := range candidateScopes {
					if err := s.workflowManifest.AuthorizeOperation(s.parentScopeSet, cand); err == nil {
						authorized = true
						break
					} else {
						authErr = err
					}
				}
				if authorized {
					authErr = nil
				}
			}
			if authErr != nil {
				writeJSONRPCError(clientOut, msg.ID, ErrCodeScopeDenied,
					fmt.Sprintf("Monotonic scope attenuation denied tool invocation: %v", authErr))
				return false
			}
		}

		// 2b. Verify coverage by active effective scopeSet
		authorized := false
		for _, cand := range candidateScopes {
			if s.scopeSet.Contains(cand) {
				authorized = true
				break
			}
		}

		if !authorized {
			toolScope := fmt.Sprintf("tool:exec:%s", params.Name)
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
	var corrJTI string
	if idStr != "" {
		s.pendingMu.Lock()
		method = s.pending[idStr]
		corrJTI = s.pendingCorrelationJTI[idStr]
		delete(s.pending, idStr)
		delete(s.pendingCorrelationJTI, idStr)
		s.pendingMu.Unlock()
	}
	if corrJTI == "" {
		corrJTI = s.activeCorrelationJTI
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

	// 2. Outbound trace header (X-Correlation-JTI) injection into _meta for result objects
	if corrJTI != "" && len(msg.Result) > 0 && bytes.HasPrefix(bytes.TrimSpace(msg.Result), []byte("{")) {
		var resObj map[string]any
		if err := json.Unmarshal(msg.Result, &resObj); err == nil {
			metaMap, ok := resObj["_meta"].(map[string]any)
			if !ok {
				metaMap = make(map[string]any)
			}
			metaMap["X-Correlation-JTI"] = corrJTI
			resObj["_meta"] = metaMap
			if newResultBytes, err := json.Marshal(resObj); err == nil {
				msg.Result = newResultBytes
				if newMsgBytes, err := json.Marshal(msg); err == nil {
					line = newMsgBytes
				}
			}
		}
	}

	// 3. Secret Redaction on tool outputs
	if s.cfg.ScrubSecrets && s.sanitizer != nil {
		scrubbed, modified := s.sanitizer.ScrubSecrets(line)
		if modified {
			return scrubbed
		}
	}

	return line
}

// extractToolCandidateScopes computes structured candidate scopes for an MCP tool name.
func extractToolCandidateScopes(toolName string) []attenuation.Scope {
	var scopes []attenuation.Scope
	seen := make(map[string]bool)

	addScope := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || seen[trimmed] {
			return
		}
		s, err := attenuation.ParseScope(trimmed)
		if err == nil {
			seen[trimmed] = true
			scopes = append(scopes, s)
		}
	}

	// 1. Standard MCP tool scope: "tool:exec:<name>"
	addScope(fmt.Sprintf("tool:exec:%s", toolName))

	// 2. Direct scope: "<name>" if it already adheres to domain:action format
	addScope(toolName)

	// 3. Normalization of common naming patterns:
	// e.g. "merge_request:approve", "merge_request_approve", "gitlab_merge_request_approve", "git_push"
	if strings.Contains(toolName, "_") {
		lastUnderscore := strings.LastIndex(toolName, "_")
		if lastUnderscore > 0 && lastUnderscore < len(toolName)-1 {
			domainPart := toolName[:lastUnderscore]
			actionPart := toolName[lastUnderscore+1:]
			addScope(fmt.Sprintf("%s:%s", domainPart, actionPart))

			// Check stripping common platform prefixes: "gitlab_", "github_", "mcp_"
			for _, prefix := range []string{"gitlab_", "github_", "mcp_"} {
				if strings.HasPrefix(domainPart, prefix) {
					cleanDomain := strings.TrimPrefix(domainPart, prefix)
					addScope(fmt.Sprintf("%s:%s", cleanDomain, actionPart))
				}
			}
		}
	}

	return scopes
}

