package lynis

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

var ErrReportDir = errors.New("lynis report directory is not controlled")

type Request struct {
	ReportDir     string
	ApprovedItems []string
	Timeout       time.Duration
	LookPath      func(string) (string, error)
	Binary        string
}

type Result struct {
	tools.Result
	SideEffects []string `json:"side_effects"`
	ReportPath  string   `json:"report_path,omitempty"`
}

func Run(ctx context.Context, req Request) (Result, error) {
	if req.ReportDir == "" {
		return Result{}, ErrReportDir
	}
	abs, err := filepath.Abs(req.ReportDir)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return Result{}, err
	}
	before, err := snapshot(abs)
	if err != nil {
		return Result{}, err
	}
	binary := req.Binary
	if binary == "" {
		binary = "lynis"
	}
	args := []string{"audit", "system", "--quick", "--no-log", "--report-dir", abs}
	if len(req.ApprovedItems) > 0 {
		args = append(args, "--tests", strings.Join(req.ApprovedItems, ","))
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	runner := tools.Runner{
		LookPath: req.LookPath,
		Specs: map[string]tools.Spec{
			tools.ToolLynis: {Name: tools.ToolLynis, Binary: binary, Args: args, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: 1 << 20},
		},
	}
	base, err := runner.Run(ctx, tools.Request{Tool: tools.ToolLynis, HostID: "lab", ScanID: "lab"})
	if err != nil {
		return Result{Result: base}, err
	}
	after, err := snapshot(abs)
	if err != nil {
		return Result{Result: base}, err
	}
	effects := diff(before, after)
	out := Result{Result: base, SideEffects: effects}
	if len(effects) > 0 {
		out.Notes = append(out.Notes, "lynis wrote files in the controlled report directory")
		out.ReportPath = filepath.Join(abs, "lynis-report.dat")
	}
	if out.Status == domain.CollectionSuccess && len(effects) == 0 {
		out.Notes = append(out.Notes, "no report side effects were observed")
	}
	return out, nil
}

func snapshot(dir string) (map[string]os.FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]os.FileInfo{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		out[entry.Name()] = info
	}
	return out, nil
}

func diff(before, after map[string]os.FileInfo) []string {
	var out []string
	for name := range after {
		if _, ok := before[name]; !ok {
			out = append(out, name)
		}
	}
	return out
}
