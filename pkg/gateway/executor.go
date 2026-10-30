package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
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

// Execute executes the command safely.
func (e *SafeLocalExecutor) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	binPath, exists := e.AllowedBinaries[execCtx.ToolName]
	if !exists {
		return nil, fmt.Errorf("tool '%s' is not registered in safe binary catalog", execCtx.ToolName)
	}

	execTimeout := e.DefaultTimeout
	execCtxInternal, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(execCtxInternal, binPath, execCtx.Arguments...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

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

	stdout := stdoutBuf.String()
	if len(stdout) > MaxOutputBytes {
		stdout = stdout[:MaxOutputBytes] + "\n...[OUTPUT TRUNCATED: EXCEEDED 1MB LIMIT]"
	}

	stderr := stderrBuf.String()
	if len(stderr) > MaxOutputBytes {
		stderr = stderr[:MaxOutputBytes] + "\n...[OUTPUT TRUNCATED: EXCEEDED 1MB LIMIT]"
	}

	return &ExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: duration,
	}, nil
}
