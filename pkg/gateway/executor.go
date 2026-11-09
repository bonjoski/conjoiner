package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	// ErrExecutionTimeout indicates tool execution timed out.
	ErrExecutionTimeout = errors.New("tool execution timed out")
	// ErrOutputLimitExceeded indicates command output exceeded the buffer limit.
	ErrOutputLimitExceeded = errors.New("tool execution output exceeded maximum allowed size")
)

const (
	// MaxOutputBytes limits stdout/stderr to 1MB to prevent memory exhaustion attacks.
	MaxOutputBytes = 1024 * 1024
)

// syntheticPosixActions enumerates single-command POSIX utilities whose Conjoiner action verb
// is a capability label rather than a CLI subcommand token. All other multi-action tools bind
// execCtx.Action strictly as argv[0] before execCtx.Arguments.
var syntheticPosixActions = map[string]map[string]bool{
	"echo": {"print": true},
	"cat":  {"read": true},
}

// limitedBuffer caps memory growth to maxBytes during command execution so runaway child output
// can never OOM the host before cmd.Run() returns.
type limitedBuffer struct {
	buf       bytes.Buffer
	maxBytes  int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	remaining := l.maxBytes - l.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = l.buf.Write(p[:remaining])
			l.truncated = true
		} else {
			_, _ = l.buf.Write(p)
		}
	} else if origLen > 0 {
		l.truncated = true
	}
	return origLen, nil
}

func (l *limitedBuffer) StringWithNotice() string {
	if l.truncated {
		return l.buf.String() + "\n...[OUTPUT TRUNCATED: EXCEEDED 1MB LIMIT]"
	}
	return l.buf.String()
}

// ExecutionContext contains the validated parameters for tool execution.
type ExecutionContext struct {
	ToolName  string            `json:"tool"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Arguments []string          `json:"arguments"`
	Env       map[string]string `json:"env,omitempty"`
}

// ExecutionResult contains the deterministic output of a tool run.
type ExecutionResult struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
}

// ToolExecutor abstracts tool execution, separating policy verification from execution.
type ToolExecutor interface {
	Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error)
}

// MockToolExecutor provides a controllable executor for unit testing.
type MockToolExecutor struct {
	ResultFn func(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error)
}

// Execute invokes the mock execution function.
func (m *MockToolExecutor) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	if m.ResultFn != nil {
		return m.ResultFn(ctx, execCtx)
	}
	return &ExecutionResult{
		ExitCode: 0,
		Stdout:   fmt.Sprintf("executed tool '%s' with action '%s'", execCtx.ToolName, execCtx.Action),
		Stderr:   "",
		Duration: 1 * time.Millisecond,
	}, nil
}

// SafeLocalExecutor executes tools directly without invoking an intermediate shell.
// This eliminates shell injection vulnerabilities (e.g. `&&`, `;`, `|`).
type SafeLocalExecutor struct {
	AllowedBinaries map[string]string // Maps tool name to absolute binary path
	DefaultTimeout  time.Duration
}

// NewSafeLocalExecutor creates a new SafeLocalExecutor with configured allowed binaries.
func NewSafeLocalExecutor(binaries map[string]string, defaultTimeout time.Duration) *SafeLocalExecutor {
	if defaultTimeout == 0 {
		defaultTimeout = 10 * time.Second
	}
	return &SafeLocalExecutor{
		AllowedBinaries: binaries,
		DefaultTimeout:  defaultTimeout,
	}
}

func isSyntheticAction(toolName, action string) bool {
	if actions, ok := syntheticPosixActions[toolName]; ok {
		return actions[action]
	}
	return false
}

func sanitizeExecEnv(baseEnv []string) []string {
	allowedKeys := map[string]bool{
		"PATH":    true,
		"HOME":    true,
		"USER":    true,
		"LOGNAME": true,
		"TMPDIR":  true,
		"LANG":    true,
		"TERM":    true,
		"TZ":      true,
	}
	clean := make([]string, 0, 8)
	for _, entry := range baseEnv {
		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToUpper(entry[:eq])
		if allowedKeys[key] || strings.HasPrefix(key, "LC_") {
			clean = append(clean, entry)
		}
	}
	return clean
}

// Execute executes the command safely, binding argv strictly to execCtx.Action and bounding stdout/stderr memory.
func (e *SafeLocalExecutor) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	binPath, exists := e.AllowedBinaries[execCtx.ToolName]
	if !exists {
		return nil, fmt.Errorf("tool '%s' is not registered in safe binary catalog", execCtx.ToolName)
	}

	action := strings.TrimSpace(execCtx.Action)
	if strings.HasPrefix(action, "-") || strings.ContainsRune(action, '\x00') {
		return nil, fmt.Errorf("%w: invalid execution action '%s'", ErrPolicyViolation, execCtx.Action)
	}

	// CNJ-04: Bind execution argv strictly to execCtx.Action so Action="status" can never run Arguments=["push", "--force"]
	var argv []string
	if action != "" && !isSyntheticAction(execCtx.ToolName, action) {
		argv = make([]string, 0, 1+len(execCtx.Arguments))
		argv = append(argv, action)
		if len(execCtx.Arguments) > 0 && execCtx.Arguments[0] == action {
			argv = append(argv, execCtx.Arguments[1:]...)
		} else {
			argv = append(argv, execCtx.Arguments...)
		}
	} else {
		argv = append([]string(nil), execCtx.Arguments...)
	}

	if execCtx.Resource != "" && len(argv) == 0 && execCtx.ToolName == "cat" {
		argv = append(argv, "--", execCtx.Resource)
	}

	execTimeout := e.DefaultTimeout
	execCtxInternal, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(execCtxInternal, binPath, argv...)
	cmd.Env = sanitizeExecEnv(os.Environ())

	stdoutBuf := &limitedBuffer{maxBytes: MaxOutputBytes}
	stderrBuf := &limitedBuffer{maxBytes: MaxOutputBytes}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if errors.Is(execCtxInternal.Err(), context.DeadlineExceeded) {
			return nil, ErrExecutionTimeout
		} else {
			return nil, fmt.Errorf("failed executing tool '%s': %w", execCtx.ToolName, err)
		}
	}

	return &ExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.StringWithNotice(),
		Stderr:   stderrBuf.StringWithNotice(),
		Duration: duration,
	}, nil
}
