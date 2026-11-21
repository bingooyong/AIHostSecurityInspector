package openscap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

var (
	ErrContent = errors.New("openscap content pack does not match the target OS")
	ErrOffline = errors.New("openscap remediate and fetch are forbidden")
	ErrMissing = errors.New("openscap content pack is missing")
)

type Request struct {
	OS        string
	ContentID string
	ContentOS string
	Timeout   time.Duration
	LookPath  func(string) (string, error)
	Binary    string
	ExtraArgs []string
}

func Run(ctx context.Context, req Request) (tools.Result, error) {
	for _, arg := range req.ExtraArgs {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "remediate") || strings.Contains(lower, "fetch") {
			return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "forbidden_arg", Notes: []string{"offline eval only; remediate/fetch are forbidden"}}, ErrOffline
		}
	}
	if req.ContentID == "" {
		return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "missing_content"}, ErrMissing
	}
	if req.ContentOS == "" || req.OS == "" || req.ContentOS != req.OS {
		return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "content_os_mismatch", Notes: []string{"content pack must match the target OS"}}, ErrContent
	}
	binary := req.Binary
	if binary == "" {
		binary = "oscap"
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	runner := tools.Runner{
		LookPath: req.LookPath,
		Specs: map[string]tools.Spec{
			tools.ToolOpenSCAP: {Name: tools.ToolOpenSCAP, Binary: binary, Args: []string{"xccdf", "eval", "--offline", req.ContentID}, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: 1 << 20},
		},
	}
	return runner.Run(ctx, tools.Request{Tool: tools.ToolOpenSCAP})
}
