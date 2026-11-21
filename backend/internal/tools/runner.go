package tools

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

type Spec struct {
	Name        string
	Binary      string
	Args        []string
	VersionArgs []string
	Timeout     time.Duration
	MaxOutput   int
}

type Runner struct {
	LookPath func(string) (string, error)
	Specs    map[string]Spec
}

func DefaultSpecs() map[string]Spec {
	timeout := 30 * time.Second
	maxOut := 1 << 20
	return map[string]Spec{
		ToolOsquery:  {Name: ToolOsquery, Binary: "osqueryi", Args: []string{"--version"}, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: maxOut},
		ToolLynis:    {Name: ToolLynis, Binary: "lynis", Args: []string{"--version"}, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: maxOut},
		ToolOpenSCAP: {Name: ToolOpenSCAP, Binary: "oscap", Args: []string{"--version"}, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: maxOut},
		ToolClamAV:   {Name: ToolClamAV, Binary: "clamscan", Args: []string{"--version"}, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: maxOut},
		ToolYARA:     {Name: ToolYARA, Binary: "yara", Args: []string{"--version"}, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: maxOut},
	}
}

func DefaultRunner() Runner {
	return Runner{LookPath: exec.LookPath, Specs: DefaultSpecs()}
}

func (r Runner) spec(name string) (Spec, bool) {
	if r.Specs != nil {
		spec, ok := r.Specs[name]
		return spec, ok
	}
	spec, ok := DefaultSpecs()[name]
	return spec, ok
}

func (r Runner) lookPath(name string) (string, error) {
	if r.LookPath != nil {
		return r.LookPath(name)
	}
	return exec.LookPath(name)
}

func (r Runner) Run(ctx context.Context, req Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	spec, ok := r.spec(req.Tool)
	if !ok || spec.Binary == "" {
		return Result{Tool: req.Tool, Status: domain.CollectionFailed, Warning: "unknown_tool", Notes: []string{"refusing arbitrary tool execution"}}, nil
	}
	resolved, err := r.lookPath(spec.Binary)
	if err != nil || resolved == "" {
		return Result{
			Tool: req.Tool, Status: domain.CollectionNotAvailable, Warning: "tool_not_installed", Findings: 0,
			Notes: []string{"approved tool binary was not found", "missing tool cannot be reported as a clean scan"},
		}, nil
	}
	if filepath.Base(resolved) != spec.Binary {
		return Result{Tool: req.Tool, Status: domain.CollectionFailed, Warning: "binary_mismatch", Notes: []string{"resolved binary name is not on the allowlist"}}, nil
	}

	version := ""
	if len(spec.VersionArgs) > 0 {
		vctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, _, _, verr := r.runCmd(vctx, resolved, spec.VersionArgs, 4096)
		cancel()
		if verr == nil {
			version = firstLine(out)
		}
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	maxOut := spec.MaxOutput
	if maxOut <= 0 {
		maxOut = 1 << 20
	}
	stdout, stderr, exitCode, runErr := r.runCmd(runCtx, resolved, append([]string{}, spec.Args...), maxOut)
	result := Result{Tool: req.Tool, Findings: 0, Notes: []string{}, Output: stdout}
	if version != "" {
		result.Notes = append(result.Notes, "version: "+version)
	}
	if errors.Is(runErr, errOutputLimit) {
		result.Status = domain.CollectionFailed
		result.Warning = "output_limit"
		result.Notes = append(result.Notes, "tool output exceeded the byte limit and is not a clean scan")
		return result, nil
	}
	if runCtx.Err() != nil && (errors.Is(runCtx.Err(), context.DeadlineExceeded) || errors.Is(runErr, context.DeadlineExceeded)) {
		result.Status = domain.CollectionTimeout
		result.Warning = "timeout"
		result.Notes = append(result.Notes, "tool exceeded its timeout and was process-group cancelled")
		return result, nil
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if runErr != nil && exitCode == 0 {
		result.Status = domain.CollectionFailed
		result.Warning = "execution_error"
		result.Notes = append(result.Notes, "tool execution failed")
		return result, nil
	}
	result.Notes = append(result.Notes, "exit_code: "+strconv.Itoa(exitCode))
	if exitCode != 0 {
		result.Status = domain.CollectionFailed
		result.Warning = "nonzero_exit"
		if stderr != "" {
			result.Notes = append(result.Notes, "stderr captured")
		}
		_ = stdout
		return result, nil
	}
	result.Status = domain.CollectionSuccess
	result.Notes = append(result.Notes, "readonly allowlisted execution completed")
	return result, nil
}

var errOutputLimit = errors.New("output limit exceeded")

func (r Runner) runCmd(ctx context.Context, bin string, args []string, maxOut int) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout := &capWriter{limit: maxOut}
	stderr := &capWriter{limit: maxOut}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return stdout.buf.String(), stderr.buf.String(), -1, errOutputLimit
	}
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return stdout.buf.String(), stderr.buf.String(), -1, err
		}
	}
	return stdout.buf.String(), stderr.buf.String(), exitCode, nil
}

type capWriter struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.exceeded {
		return len(p), errOutputLimit
	}
	if w.buf.Len()+len(p) > w.limit {
		remain := w.limit - w.buf.Len()
		if remain > 0 {
			w.buf.Write(p[:remain])
		}
		w.exceeded = true
		return len(p), errOutputLimit
	}
	return w.buf.Write(p)
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return s[:i]
		}
	}
	return s
}
