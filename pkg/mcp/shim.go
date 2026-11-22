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
	"github.com/bonjoski/conjoiner/pkg/containment"
	"github.com/bonjoski/conjoiner/pkg/ledger"
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
	RequireSessionNonce     bool
	NonceTracker            *token.SessionNonceTracker
	Ledger                  ledger.Ledger
	WorkspaceRoot           string
	PathValidator           containment.InodeValidator
	RequireDPoP             bool
	DPoPReplayCache         token.ReplayCache
	DPoPMaxSkew             time.Duration
	UBMCPv1Errors           bool
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
	nonceTracker          *token.SessionNonceTracker
	ledger                ledger.Ledger
	workspaceRoot         string
	pathValidator         containment.InodeValidator
	dpopReplayCache       token.ReplayCache
	dpopMaxSkew           time.Duration
	ubMCPv1Errors         bool
	lastSIRID             string
	pendingSIRID          map[string]string
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

	nonceTracker := cfg.NonceTracker
	if nonceTracker == nil {
		nonceTracker = token.NewSessionNonceTracker(token.NewMemoryReplayCache(), 60*time.Second)
	}

	if strings.TrimSpace(cfg.SessionID) == "" {
		if fabSess := strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID")); fabSess != "" {
			cfg.SessionID = fabSess
		}
	}

	wsRoot := strings.TrimSpace(cfg.WorkspaceRoot)
	pathVal := cfg.PathValidator
	if wsRoot != "" && pathVal == nil {
		pathVal = containment.NewStrictPathValidator()
	}

	dpopCache := cfg.DPoPReplayCache
	if dpopCache == nil {
		dpopCache = token.NewMemoryReplayCache()
	}
	dpopSkew := cfg.DPoPMaxSkew
	if dpopSkew <= 0 {
		dpopSkew = 30 * time.Second
	}

	ubMCPv1 := cfg.UBMCPv1Errors || cfg.Ledger != nil || wsRoot != "" || cfg.RequireDPoP

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
		nonceTracker:          nonceTracker,
		ledger:                cfg.Ledger,
		workspaceRoot:         wsRoot,
		pathValidator:         pathVal,
		dpopReplayCache:       dpopCache,
		dpopMaxSkew:           dpopSkew,
		ubMCPv1Errors:         ubMCPv1,
		pendingSIRID:          make(map[string]string),
		pending:               make(map[string]string),
	}, nil
}

// ActiveCorrelationJTI returns the currently tracked correlation JTI.
func (s *TransportShim) ActiveCorrelationJTI() string {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return s.activeCorrelationJTI
}

// LastSIRID returns the most recently issued Conjoiner SIR ID formatted for BLPR-v1 lineage.
func (s *TransportShim) LastSIRID() string {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return s.lastSIRID
}

func (s *TransportShim) resolveSessionID() string {
	if s.verifiedToken != nil && strings.TrimSpace(s.verifiedToken.SessionID) != "" {
		return strings.TrimSpace(s.verifiedToken.SessionID)
	}
	if strings.TrimSpace(s.cfg.SessionID) != "" {
		return strings.TrimSpace(s.cfg.SessionID)
	}
	if fab := strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID")); fab != "" {
		return fab
	}
	return ""
}

func setEnvVar(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func (s *TransportShim) buildChildEnv(environ []string) []string {
	clean := SanitizeChildEnv(environ)
	sessID := s.resolveSessionID()
	if sessID != "" {
		clean = setEnvVar(clean, "FABRIAL_SESSION_ID", sessID)
	}

	sirID := s.LastSIRID()
	if sirID == "" && s.ledger != nil {
		sessionForSIR := sessID
		if sessionForSIR == "" {
			sessionForSIR = "default"
		}
		agentID := "mcp-shim"
		if s.verifiedToken != nil && s.verifiedToken.Subject != "" {
			agentID = s.verifiedToken.Subject
		}
		rec, err := s.ledger.Record(context.Background(), ledger.IntentRecord{
			SessionID:     sessionForSIR,
			AgentIdentity: agentID,
			ToolName:      "mcp-shim:session",
			Action:        "session/start",
			Resource:      s.cfg.TargetCommand,
			Verdict:       ledger.VerdictAllow,
		})
		if err == nil && rec != nil {
			sirID = FormatBLPRReceiptID(rec.ReceiptID)
			s.pendingMu.Lock()
			s.lastSIRID = sirID
			s.pendingMu.Unlock()
		}
	}
	if sirID != "" {
		clean = setEnvVar(clean, "CONJOINER_SIR_ID", sirID)
	}
	return clean
}

// Run executes the target command subprocess and transparently pipes stdin/stdout through security filters.
func (s *TransportShim) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, clientErr io.Writer) error {
	cmd := exec.CommandContext(ctx, s.cfg.TargetCommand, s.cfg.TargetArgs...)
	cmd.Env = s.buildChildEnv(os.Environ())

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

func (s *TransportShim) writeToolDenial(w io.Writer, id json.RawMessage, legacyCode int, legacyMessage string, ubErr UBMCPv1Error) {
	if w == nil {
		return
	}
	toolRes := NewUBMCPv1ErrorResult(ubErr)
	if s.ubMCPv1Errors {
		resp, err := NewSuccessResponse(id, toolRes)
		if err != nil {
			return
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			return
		}
		respBytes = append(respBytes, '\n')
		_, _ = w.Write(respBytes)
		return
	}

	errResp := NewErrorResponseWithData(id, legacyCode, legacyMessage, toolRes.StructuredContent)
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
				forwarded, shouldForward := s.processInboundLine(trimmed, clientOut)
				if !shouldForward {
					continue
				}
				if !bytes.HasSuffix(forwarded, []byte("\n")) {
					forwarded = append(forwarded, '\n')
				}
				if _, wErr := serverIn.Write(forwarded); wErr != nil {
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
// If permitted and serverIn is non-nil, writes the (potentially lineage-enriched) frame to serverIn.
func (s *TransportShim) HandleInboundLine(line []byte, serverIn io.Writer, clientOut io.Writer) bool {
	return s.handleInboundLine(line, serverIn, clientOut)
}

// HandleOutboundLine inspects, tags trace metadata, and sanitizes an outbound JSON-RPC message.
func (s *TransportShim) HandleOutboundLine(line []byte) []byte {
	return s.handleOutboundLine(line)
}

func (s *TransportShim) handleInboundLine(line []byte, serverIn io.Writer, clientOut io.Writer) bool {
	forwarded, ok := s.processInboundLine(line, clientOut)
	if ok && serverIn != nil {
		if !bytes.HasSuffix(forwarded, []byte("\n")) {
			forwarded = append(forwarded, '\n')
		}
		_, _ = serverIn.Write(forwarded)
	}
	return ok
}

func (s *TransportShim) recordSIR(sessionID, toolName, dpopSig string, rawArgs json.RawMessage, verdict ledger.PolicyVerdict, reason string) string {
	if s.ledger == nil {
		return ""
	}
	if strings.TrimSpace(sessionID) == "" {
		sessionID = "default"
	}
	agentID := "mcp-agent"
	if s.verifiedToken != nil && s.verifiedToken.Subject != "" {
		agentID = s.verifiedToken.Subject
	}
	var argSlice []string
	if len(rawArgs) > 0 {
		argSlice = []string{string(rawArgs)}
	}
	intent := ledger.IntentRecord{
		SessionID:      sessionID,
		AgentIdentity:  agentID,
		ToolName:       toolName,
		Action:         "tools/call",
		ArgumentDigest: ledger.ComputeArgumentDigest(toolName, "tools/call", "", argSlice),
		DPoPSignature:  dpopSig,
		Verdict:        verdict,
		RejectionReason: reason,
	}

	var receiptID string
	if verdict == ledger.VerdictAllow {
		if rec, err := s.ledger.Record(context.Background(), intent); err == nil && rec != nil {
			receiptID = FormatBLPRReceiptID(rec.ReceiptID)
		}
	} else {
		if proof, err := s.ledger.RecordRejection(context.Background(), intent); err == nil && proof != nil && proof.Receipt != nil {
			receiptID = FormatBLPRReceiptID(proof.Receipt.ReceiptID)
		}
	}
	if receiptID != "" {
		s.pendingMu.Lock()
		s.lastSIRID = receiptID
		s.pendingMu.Unlock()
	}
	return receiptID
}

func sanitizeSafeToolLabel(toolName string) string {
	clean := sanitizeUBText(toolName)
	if clean == "" || len(clean) > 64 {
		return "<redacted-tool>"
	}
	if injected, _ := DetectPromptInjection(clean); injected {
		return "<redacted-tool>"
	}
	for _, r := range clean {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == ':' || r == '.') {
			return "<redacted-tool>"
		}
	}
	return clean
}

var pathArgumentKeys = map[string]bool{
	"path":          true,
	"file":          true,
	"file_path":     true,
	"filepath":      true,
	"target_path":   true,
	"target":        true,
	"dir":           true,
	"directory":     true,
	"workspace":     true,
	"root":          true,
	"manifest_path": true,
	"output":        true,
	"dest":          true,
	"source":        true,
	"src":           true,
}

func (s *TransportShim) validateArgumentPaths(rawArgs json.RawMessage) error {
	if s.workspaceRoot == "" || s.pathValidator == nil || len(rawArgs) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(rawArgs, &decoded); err != nil {
		return nil
	}
	return s.walkAndValidatePaths(decoded)
}

func (s *TransportShim) walkAndValidatePaths(v any) error {
	switch node := v.(type) {
	case map[string]any:
		for k, val := range node {
			if pathArgumentKeys[strings.ToLower(strings.TrimSpace(k))] {
				if p, ok := val.(string); ok && strings.TrimSpace(p) != "" {
					if _, err := s.pathValidator.ValidatePath(s.workspaceRoot, p); err != nil {
						return err
					}
				}
			}
			if err := s.walkAndValidatePaths(val); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range node {
			if err := s.walkAndValidatePaths(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func injectLineageIntoInboundFrame(trimmed []byte, sessionID, sirID string) []byte {
	if sessionID == "" && sirID == "" {
		return trimmed
	}
	var msgObj map[string]any
	if err := json.Unmarshal(trimmed, &msgObj); err != nil {
		return trimmed
	}
	paramsObj, ok := msgObj["params"].(map[string]any)
	if !ok {
		return trimmed
	}
	metaObj, ok := paramsObj["_meta"].(map[string]any)
	if !ok {
		metaObj = make(map[string]any)
	}
	if sessionID != "" {
		metaObj["FABRIAL_SESSION_ID"] = sessionID
	}
	if sirID != "" {
		metaObj["CONJOINER_SIR_ID"] = sirID
	}
	paramsObj["_meta"] = metaObj
	msgObj["params"] = paramsObj
	out, err := json.Marshal(msgObj)
	if err != nil {
		return trimmed
	}
	return out
}

// processInboundLine checks permissions, DPoP, path containment, taint, and prompt injection on inbound client messages.
// Fails closed (returns nil, false and writes an error/UB-MCP-v1 CallToolResult) on batch arrays, malformed JSON, or policy violations.
func (s *TransportShim) processInboundLine(line []byte, clientOut io.Writer) ([]byte, bool) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, false
	}

	// CNJ-03: Explicitly reject JSON-RPC batch arrays `[...]` (fail closed)
	if trimmed[0] == '[' {
		writeJSONRPCError(clientOut, nil, ErrCodeInvalidRequest, "Conjoiner policy rejected JSON-RPC batch array: single-request framing required")
		return nil, false
	}
	if trimmed[0] != '{' {
		writeJSONRPCError(clientOut, nil, ErrCodeParseError, "Conjoiner policy rejected non-object JSON-RPC frame")
		return nil, false
	}

	if hasDuplicateJSONKeys(trimmed) {
		writeJSONRPCError(clientOut, nil, ErrCodeInvalidRequest, "Conjoiner policy rejected JSON-RPC frame with duplicate object keys")
		return nil, false
	}

	var msg JSONRPCMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		writeJSONRPCError(clientOut, nil, ErrCodeParseError, "Conjoiner policy rejected malformed JSON-RPC message")
		return nil, false
	}

	if msg.JSONRPC != "" && msg.JSONRPC != "2.0" {
		writeJSONRPCError(clientOut, msg.ID, ErrCodeInvalidRequest, "Unsupported JSON-RPC version")
		return nil, false
	}

	// Enforce live token TTL when configured with a verified TaskToken
	if s.verifiedToken != nil && s.verifiedToken.IsExpired(time.Now().UTC()) {
		if msg.Method == "tools/call" && s.ubMCPv1Errors {
			sirID := s.recordSIR(s.resolveSessionID(), "tools/call", "", nil, ledger.VerdictDenyScope, "task token expired")
			s.writeToolDenial(clientOut, msg.ID, ErrCodeTokenExpired, "Conjoiner task token has expired", UBMCPv1Error{
				Code:           "CONJOINER_TOKEN_EXPIRED",
				ExitCode:       ExitCodePolicyDeny,
				Retryable:      true,
				Summary:        "Paused tool call: Conjoiner ephemeral task token has expired.",
				RemediationCmd: "conjoiner token issue --ttl 30s",
				Why:            "Ephemeral 30-second tokens limit blast radius and must be refreshed before invoking tools.",
				ReceiptID:      sirID,
			})
			return nil, false
		}
		writeJSONRPCError(clientOut, msg.ID, ErrCodeTokenExpired, "Conjoiner task token has expired")
		return nil, false
	}

	// Enforce live token revocation when configured with a verified TaskToken
	if s.verifiedToken != nil && s.revocationStore != nil && s.revocationStore.IsRevoked(s.verifiedToken.JTI, s.verifiedToken.SessionID, s.verifiedToken.Subject) {
		if msg.Method == "tools/call" && s.ubMCPv1Errors {
			sirID := s.recordSIR(s.resolveSessionID(), "tools/call", "", nil, ledger.VerdictDenyScope, "task token revoked")
			s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation, "Conjoiner task token has been revoked", UBMCPv1Error{
				Code:           "CONJOINER_TOKEN_REVOKED",
				ExitCode:       ExitCodePolicyDeny,
				Retryable:      false,
				Summary:        "Paused tool call: Conjoiner task token has been revoked.",
				RemediationCmd: "fabrial session begin",
				Why:            "Revoked tokens are permanently rejected to halt compromised or ended agent sessions.",
				ReceiptID:      sirID,
			})
			return nil, false
		}
		writeJSONRPCError(clientOut, msg.ID, ErrCodePolicyViolation, "Conjoiner task token has been revoked")
		return nil, false
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
		s.pendingMu.Lock()
		s.activeCorrelationJTI = reqJTI
		s.pendingMu.Unlock()
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
		return nil, false
	}

	if msg.Method == "tools/call" {
		paramsTrim := bytes.TrimSpace(msg.Params)
		if len(paramsTrim) == 0 || paramsTrim[0] != '{' {
			writeJSONRPCError(clientOut, msg.ID, ErrCodeInvalidParams, "Malformed or missing tools/call params object")
			return nil, false
		}

		var params ToolCallParams
		if err := json.Unmarshal(paramsTrim, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			writeJSONRPCError(clientOut, msg.ID, ErrCodeInvalidParams, "Invalid tools/call parameters: tool name is required")
			return nil, false
		}

		activeSessionID := s.resolveSessionID()
		if activeSessionID == "" && s.verifiedToken != nil && s.verifiedToken.Subject != "" {
			activeSessionID = s.verifiedToken.Subject
		}

		// 0a. Validate Token/Session revocation status on tool dispatch
		if s.revocationStore != nil {
			checkJTI := s.ActiveCorrelationJTI()
			checkSID := activeSessionID
			checkSub := ""
			if s.verifiedToken != nil {
				checkJTI = s.verifiedToken.JTI
				checkSID = s.verifiedToken.SessionID
				checkSub = s.verifiedToken.Subject
			}
			if s.revocationStore.IsRevoked(checkJTI, checkSID, checkSub) {
				sirID := s.recordSIR(activeSessionID, params.Name, "", params.Arguments, ledger.VerdictDenyScope, "task token revoked")
				s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
					"Conjoiner policy blocked tool call: task token has been revoked",
					UBMCPv1Error{
						Code:           "CONJOINER_TOKEN_REVOKED",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      false,
						Summary:        "Paused tool call: task token has been revoked.",
						RemediationCmd: "fabrial session begin",
						Why:            "Revoked tokens are immediately blocked across all MCP tool calls.",
						ReceiptID:      sirID,
					})
				return nil, false
			}
		}

		// 0b. Zero-Background-Authority: Hardware Presence Check
		if s.cfg.RequireHardwarePresence {
			checker := s.presenceChecker
			if checker == nil {
				checker = NewDefaultPresenceChecker()
			}
			if err := checker.CheckPresence(context.Background()); err != nil {
				LogPresenceRejection(s.cfg.AuditLogPath, params.Name, activeSessionID, err)
				sirID := s.recordSIR(activeSessionID, params.Name, "", params.Arguments, ledger.VerdictDenyScope, "hardware presence failed")
				s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
					"Zero-Background-Authority: User presence failed / locked",
					UBMCPv1Error{
						Code:           "CONJOINER_PRESENCE_REQUIRED",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      true,
						Summary:        "Paused tool call: active local user presence is required while workstation is unlocked.",
						RemediationCmd: "conjoiner explain dpop --why",
						Why:            "Zero-Background-Authority prevents unattended agents from invoking tools while the workstation is locked.",
						ReceiptID:      sirID,
					})
				return nil, false
			}
		}

		// 0c. Session-Bound Nonce & DPoP Proof Extraction
		var authMetaHolder struct {
			Nonce string `json:"nonce"`
			DPoP  string `json:"dpop"`
			Meta  struct {
				Nonce        string `json:"nonce"`
				SessionNonce string `json:"session_nonce"`
				DPoP         string `json:"dpop"`
				DPoPAlt      string `json:"DPoP"`
			} `json:"_meta"`
		}
		var callNonce, callDPoP string
		if err := json.Unmarshal(paramsTrim, &authMetaHolder); err == nil {
			if authMetaHolder.Nonce != "" {
				callNonce = authMetaHolder.Nonce
			} else if authMetaHolder.Meta.Nonce != "" {
				callNonce = authMetaHolder.Meta.Nonce
			} else if authMetaHolder.Meta.SessionNonce != "" {
				callNonce = authMetaHolder.Meta.SessionNonce
			}
			if authMetaHolder.DPoP != "" {
				callDPoP = authMetaHolder.DPoP
			} else if authMetaHolder.Meta.DPoP != "" {
				callDPoP = authMetaHolder.Meta.DPoP
			} else if authMetaHolder.Meta.DPoPAlt != "" {
				callDPoP = authMetaHolder.Meta.DPoPAlt
			}
		}

		if s.cfg.RequireSessionNonce && callNonce == "" {
			sirID := s.recordSIR(activeSessionID, params.Name, "", params.Arguments, ledger.VerdictDenyScope, "missing required session-bound nonce")
			s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
				"Conjoiner policy blocked tool call: missing required session-bound nonce",
				UBMCPv1Error{
					Code:           "CONJOINER_NONCE_REQUIRED",
					ExitCode:       ExitCodePolicyDeny,
					Retryable:      true,
					Summary:        "Paused tool call: missing required session-bound anti-replay nonce.",
					RemediationCmd: "conjoiner explain dpop --why",
					Why:            "Session-bound nonces prevent replayed tool invocations across MCP sessions.",
					ReceiptID:      sirID,
				})
			return nil, false
		}

		if callNonce != "" {
			if err := s.nonceTracker.ValidateAndConsume(activeSessionID, callNonce); err != nil {
				sirID := s.recordSIR(activeSessionID, params.Name, "", params.Arguments, ledger.VerdictDenyScope, "session-bound nonce validation failed")
				if errors.Is(err, token.ErrReplayDetected) {
					s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
						"Conjoiner policy blocked tool call: tool call replay detected (nonce already consumed)",
						UBMCPv1Error{
							Code:           "CONJOINER_NONCE_REPLAY",
							ExitCode:       ExitCodePolicyDeny,
							Retryable:      true,
							Summary:        "Paused tool call: replayed session-bound nonce detected.",
							RemediationCmd: "conjoiner explain dpop --why",
							Why:            "Each session-bound nonce can be consumed only once to neutralize replay attacks.",
							ReceiptID:      sirID,
						})
					return nil, false
				}
				s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
					fmt.Sprintf("Conjoiner policy blocked tool call: invalid session-bound nonce: %v", err),
					UBMCPv1Error{
						Code:           "CONJOINER_NONCE_INVALID",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      true,
						Summary:        "Paused tool call: session-bound nonce failed validation.",
						RemediationCmd: "conjoiner explain dpop --why",
						Why:            "Tool calls must present a fresh nonce bound to the active session identifier.",
						ReceiptID:      sirID,
					})
				return nil, false
			}
		}

		// 0d. RFC 9449 DPoP Proof Validation
		if s.cfg.RequireDPoP || callDPoP != "" {
			if strings.TrimSpace(callDPoP) == "" {
				sirID := s.recordSIR(activeSessionID, params.Name, "", params.Arguments, ledger.VerdictDenyScope, "missing required DPoP proof")
				s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
					"Conjoiner policy blocked tool call: missing required RFC 9449 DPoP proof",
					UBMCPv1Error{
						Code:           "CONJOINER_DPOP_INVALID",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      true,
						Summary:        "Paused tool call: missing required RFC 9449 DPoP proof.",
						RemediationCmd: "conjoiner explain dpop --why",
						Why:            "DPoP binds each tool invocation to the agent's ephemeral Ed25519 keypair to defeat bearer token theft.",
						ReceiptID:      sirID,
					})
				return nil, false
			}
			_, jwk, dpopErr := token.ValidateProofWithNonce(
				callDPoP,
				MCPDPoPMethod,
				MCPDPoPURI(params.Name),
				s.cfg.Token,
				callNonce,
				s.dpopMaxSkew,
				s.dpopReplayCache,
				time.Now().UTC(),
			)
			if dpopErr == nil && s.verifiedToken != nil && s.verifiedToken.CNF.JKT != "" {
				if !s.verifiedToken.VerifyDPoPBinding(jwk.Thumbprint()) {
					dpopErr = errors.New("DPoP key thumbprint does not match task token cnf.jkt binding")
				}
			}
			if dpopErr != nil {
				sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictDenyScope, "DPoP validation failed")
				s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
					"Conjoiner policy blocked tool call: RFC 9449 DPoP proof failed verification",
					UBMCPv1Error{
						Code:           "CONJOINER_DPOP_INVALID",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      true,
						Summary:        "Paused tool call: RFC 9449 DPoP proof failed verification.",
						RemediationCmd: "conjoiner explain dpop --why",
						Why:            "DPoP proof signatures, URI bindings, freshness, and key thumbprints must verify before executing tools.",
						ReceiptID:      sirID,
					})
				return nil, false
			}
		}

		// 1. Semantic firewall: check tool name and arguments (raw + decoded JSON strings) for prompt injection
		if injected, reason := DetectPromptInjection(params.Name); injected {
			sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictDenyDrift, "prompt injection in tool name")
			s.writeToolDenial(clientOut, msg.ID, ErrCodePromptInjectionDetected,
				fmt.Sprintf("Conjoiner policy blocked tool call: %s", reason),
				UBMCPv1Error{
					Code:           "CONJOINER_DENY_DRIFT",
					ExitCode:       ExitCodePolicyDeny,
					Retryable:      false,
					Summary:        "Paused tool call: prompt-injection or unauthorized reflection pattern detected in tool name.",
					RemediationCmd: "conjoiner explain mcp --why",
					Why:            "Conjoiner blocks prompt-injection directives and role markers before forwarding requests to MCP servers.",
					ReceiptID:      sirID,
				})
			return nil, false
		}
		if len(params.Arguments) > 0 {
			if injected, reason := DetectJSONPromptInjection(params.Arguments); injected {
				sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictDenyDrift, "prompt injection in tool arguments")
				s.writeToolDenial(clientOut, msg.ID, ErrCodePromptInjectionDetected,
					fmt.Sprintf("Conjoiner policy blocked tool call: %s", reason),
					UBMCPv1Error{
						Code:           "CONJOINER_DENY_DRIFT",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      false,
						Summary:        "Paused tool call: prompt-injection or unauthorized reflection pattern detected in arguments.",
						RemediationCmd: "conjoiner explain mcp --why",
						Why:            "Untrusted tool arguments containing instruction overrides or role tags are blocked fail-closed.",
						ReceiptID:      sirID,
					})
				return nil, false
			}
		}

		// 1b. Dynamic Taint Gate: intercept multi-step exfiltration on egress tools
		if s.taintGate != nil && IsEgressToolName(params.Name) {
			taintSessionID := activeSessionID
			if taintSessionID == "" {
				taintSessionID = "default"
			}
			if allowed, reason := s.taintGate.EvaluateEgress(taintSessionID, params.Name, params.Arguments); !allowed {
				sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictDenyDrift, "taint gate egress violation")
				s.writeToolDenial(clientOut, msg.ID, ErrCodeTaintViolation,
					fmt.Sprintf("Conjoiner policy blocked egress: %s", reason),
					UBMCPv1Error{
						Code:           "CONJOINER_DENY_DRIFT",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      false,
						Summary:        "Paused outbound egress tool call: sensitive session data or high-entropy secret detected.",
						RemediationCmd: "conjoiner explain blast-radius --why",
						Why:            "Conjoiner's dynamic taint gate prevents multi-step exfiltration of sensitive files read earlier in the session.",
						ReceiptID:      sirID,
					})
				return nil, false
			}
		}

		// 1c. Path Containment Validation (repo confinement against dot-dot & symlink escapes)
		if err := s.validateArgumentPaths(params.Arguments); err != nil {
			sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictDenyDrift, "path containment escape")
			s.writeToolDenial(clientOut, msg.ID, ErrCodePolicyViolation,
				fmt.Sprintf("Conjoiner policy blocked tool call: %v", err),
				UBMCPv1Error{
					Code:           "CONJOINER_PATH_CONTAINMENT_DENY",
					ExitCode:       ExitCodePolicyDeny,
					Retryable:      true,
					Summary:        "Paused tool call: requested file path escapes the confined workspace root.",
					RemediationCmd: "conjoiner gate confinement --root . --path <relative-path>",
					Why:            "All MCP file paths must resolve strictly inside the canonical repository root without traversal or outside symlinks.",
					ReceiptID:      sirID,
				})
			return nil, false
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
				sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictDenyScope, "workflow manifest denied scope")
				safeTool := sanitizeSafeToolLabel(params.Name)
				s.writeToolDenial(clientOut, msg.ID, ErrCodeScopeDenied,
					fmt.Sprintf("Monotonic scope attenuation denied tool invocation: %v", authErr),
					UBMCPv1Error{
						Code:           "CONJOINER_DENY_SCOPE",
						ExitCode:       ExitCodePolicyDeny,
						Retryable:      false,
						Summary:        fmt.Sprintf("Paused tool '%s': operation is outside the workflow manifest scope.", safeTool),
						RemediationCmd: "conjoiner explain scope --why",
						Why:            "Monotonic workflow attenuation blocks state-mutating or unpermitted operations outside the granted scope intersection.",
						ReceiptID:      sirID,
					})
				return nil, false
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
			sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictDenyScope, "monotonic scope attenuation denied")
			safeTool := sanitizeSafeToolLabel(params.Name)
			s.writeToolDenial(clientOut, msg.ID, ErrCodeScopeDenied,
				fmt.Sprintf("Monotonic scope attenuation denied tool invocation: %s (required: %s)", params.Name, toolScope),
				UBMCPv1Error{
					Code:           "CONJOINER_DENY_SCOPE",
					ExitCode:       ExitCodePolicyDeny,
					Retryable:      false,
					Summary:        fmt.Sprintf("Paused tool '%s': capability is outside granted monotonic scope.", safeTool),
					RemediationCmd: "conjoiner explain scope --why",
					Why:            "Subagent tool invocations require an explicit matching scope within the attenuated delegation chain.",
					ReceiptID:      sirID,
				})
			return nil, false
		}

		// 3. Allowed tool call: record SignedIntentReceipt (ALLOW) and propagate FABRIAL_SESSION_ID + CONJOINER_SIR_ID
		sirID := s.recordSIR(activeSessionID, params.Name, callDPoP, params.Arguments, ledger.VerdictAllow, "")
		if idStr != "" && sirID != "" {
			s.pendingMu.Lock()
			s.pendingSIRID[idStr] = sirID
			s.pendingMu.Unlock()
		}

		enriched := injectLineageIntoInboundFrame(trimmed, activeSessionID, sirID)
		return enriched, true
	}

	return trimmed, true
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
	var sirID string
	if idStr != "" {
		s.pendingMu.Lock()
		method = s.pending[idStr]
		corrJTI = s.pendingCorrelationJTI[idStr]
		sirID = s.pendingSIRID[idStr]
		delete(s.pending, idStr)
		delete(s.pendingCorrelationJTI, idStr)
		delete(s.pendingSIRID, idStr)
		s.pendingMu.Unlock()
	}
	if corrJTI == "" {
		corrJTI = s.ActiveCorrelationJTI()
	}
	if sirID == "" {
		sirID = s.LastSIRID()
	}
	sessID := s.resolveSessionID()

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

	// 2. Outbound trace & BLPR-v1 lineage header injection into _meta for result objects
	if (corrJTI != "" || sessID != "" || sirID != "") && len(msg.Result) > 0 && bytes.HasPrefix(bytes.TrimSpace(msg.Result), []byte("{")) {
		var resObj map[string]any
		if err := json.Unmarshal(msg.Result, &resObj); err == nil {
			metaMap, ok := resObj["_meta"].(map[string]any)
			if !ok {
				metaMap = make(map[string]any)
			}
			if corrJTI != "" {
				metaMap["X-Correlation-JTI"] = corrJTI
			}
			if sessID != "" {
				metaMap["FABRIAL_SESSION_ID"] = sessID
			}
			if sirID != "" {
				metaMap["CONJOINER_SIR_ID"] = sirID
			}
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

