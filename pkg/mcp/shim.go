package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/bonjoski/conjoiner/pkg/attenuation"
)

var (
	// ErrMissingTargetCommand indicates no command was specified to run.
	ErrMissingTargetCommand = errors.New("missing target command to execute")
)

// Config configures the transparent MCP transport shim.
type Config struct {
	TargetCommand  string
	TargetArgs     []string
	AllowedScopes  []string
	Token          string
	MaxMessageSize int64
	ScrubSecrets   bool
}

// TransportShim coordinates bidirectional streaming JSON-RPC inspection.
type TransportShim struct {
	cfg       Config
	scopeSet  attenuation.ScopeSet
	sanitizer *Sanitizer
	pendingMu sync.Mutex
	pending   map[string]string // maps request ID string to method name
}

// NewTransportShim constructs a verified MCP transport shim.
func NewTransportShim(cfg Config) (*TransportShim, error) {
	if cfg.TargetCommand == "" {
		return nil, ErrMissingTargetCommand
	}
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = 10 * 1024 * 1024 // 10MB
	}

	// Resolve scopes: fallback to ambient CONJOINER_SCOPES if empty
	rawScopes := cfg.AllowedScopes
	if len(rawScopes) == 0 {
		envScopes := os.Getenv("CONJOINER_SCOPES")
		if envScopes != "" {
			rawScopes = strings.Split(envScopes, ",")
		}
	}

	// If still empty, default to allow-all wildcard "*" only if no token is set
	if len(rawScopes) == 0 && cfg.Token == "" {
		rawScopes = []string{"*"}
	}

	scopeSet, err := attenuation.NewScopeSet(rawScopes...)
	if err != nil {
		return nil, fmt.Errorf("invalid scopes: %w", err)
	}

	return &TransportShim{
		cfg:       cfg,
		scopeSet:  scopeSet,
		sanitizer: NewSanitizer(),
		pending:   make(map[string]string),
	}, nil
}

// Run executes the target command subprocess and transparently pipes stdin/stdout through security filters.
func (s *TransportShim) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, clientErr io.Writer) error {
	cmd := exec.CommandContext(ctx, s.cfg.TargetCommand, s.cfg.TargetArgs...)

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

	// Wait for streams to finish
	wg.Wait()

	// Terminate child if still running
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

// pipeClientToServer processes inbound JSON-RPC messages from client IDE to MCP server.
func (s *TransportShim) pipeClientToServer(r io.Reader, serverIn io.Writer, clientOut io.Writer) error {
	reader := bufio.NewReaderSize(r, 64*1024)

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				if shouldForward := s.handleInboundLine(trimmed, serverIn, clientOut); !shouldForward {
					// Denied message was handled by returning JSON-RPC error directly to clientOut
					continue
				}
			}
			if _, wErr := serverIn.Write(line); wErr != nil {
				return wErr
			}
		}
		if err != nil {
			return err
		}
	}
}

// handleInboundLine checks permissions and prompt injection on inbound client messages.
// Returns true if the message is authorized to be forwarded to the child process.
func (s *TransportShim) handleInboundLine(line []byte, serverIn io.Writer, clientOut io.Writer) bool {
	var msg JSONRPCMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		// Passthrough unparseable frames directly
		return true
	}

	idStr := string(msg.ID)
	if idStr != "" && msg.Method != "" {
		s.pendingMu.Lock()
		s.pending[idStr] = msg.Method
		s.pendingMu.Unlock()
	}

	if msg.Method == "tools/call" {
		var params ToolCallParams
		if err := json.Unmarshal(msg.Params, &params); err == nil {
			// 1. Semantic firewall: check tool arguments for prompt injection
			if len(params.Arguments) > 0 {
				if injected, reason := DetectPromptInjection(string(params.Arguments)); injected {
					errResp := NewErrorResponse(msg.ID, ErrCodePromptInjectionDetected, fmt.Sprintf("Conjoiner policy blocked tool call: %s", reason))
					respBytes, _ := json.Marshal(errResp)
					respBytes = append(respBytes, '\n')
					_, _ = clientOut.Write(respBytes)
					return false
				}
			}

			// 2. Monotonic scope attenuation check
			toolScope := fmt.Sprintf("tool:exec:%s", params.Name)
			reqScope, err := attenuation.ParseScope(toolScope)
			if err == nil {
				if !s.scopeSet.Contains(reqScope) {
					errResp := NewErrorResponse(msg.ID, ErrCodeScopeDenied, fmt.Sprintf("Monotonic scope attenuation denied tool invocation: %s (required: %s)", params.Name, toolScope))
					respBytes, _ := json.Marshal(errResp)
					respBytes = append(respBytes, '\n')
					_, _ = clientOut.Write(respBytes)
					return false
				}
			}
		}
	}

	return true
}

// pipeServerToClient processes outbound responses from MCP server to client IDE.
func (s *TransportShim) pipeServerToClient(r io.Reader, clientOut io.Writer) error {
	reader := bufio.NewReaderSize(r, 64*1024)

	for {
		line, err := reader.ReadBytes('\n')
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
			var filtered []ToolDef
			for _, t := range toolResult.Tools {
				tScope, err := attenuation.ParseScope(fmt.Sprintf("tool:exec:%s", t.Name))
				if err == nil && s.scopeSet.Contains(tScope) {
					filtered = append(filtered, t)
				}
			}
			toolResult.Tools = filtered
			newResultBytes, err := json.Marshal(toolResult)
			if err == nil {
				msg.Result = newResultBytes
				if newMsgBytes, err := json.Marshal(msg); err == nil {
					return newMsgBytes
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
