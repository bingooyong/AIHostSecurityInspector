package clamav

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

var (
	ErrPath       = errors.New("path is not on the approved scan list")
	ErrSignatures = errors.New("signature database is stale or missing")
	ErrMutation   = errors.New("clamav may not delete, move, or copy files")
)

type Request struct {
	Path            string
	ApprovedRoots   []string
	SignaturesUntil time.Time
	Now             time.Time
	Timeout         time.Duration
	LookPath        func(string) (string, error)
	Binary          string
	ExtraArgs       []string
}

func Run(ctx context.Context, req Request) (tools.Result, error) {
	for _, arg := range req.ExtraArgs {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "remove") || strings.Contains(lower, "move") || strings.Contains(lower, "copy") || strings.Contains(lower, "delete") {
			return tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "mutation_forbidden"}, ErrMutation
		}
	}
	if req.SignaturesUntil.IsZero() || req.Now.After(req.SignaturesUntil) {
		return tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "stale_signatures", Notes: []string{"signature database is stale; missing intel cannot be a clean scan"}}, ErrSignatures
	}
	abs, err := filepath.Abs(req.Path)
	if err != nil {
		return tools.Result{}, err
	}
	if !approvedPath(abs, req.ApprovedRoots) {
		return tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "path_not_approved"}, ErrPath
	}
	if _, err := os.Stat(abs); err != nil {
		return tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "path_missing"}, err
	}
	binary := req.Binary
	if binary == "" {
		binary = "clamdscan"
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	runner := tools.Runner{
		LookPath: req.LookPath,
		Specs: map[string]tools.Spec{
			tools.ToolClamAV: {Name: tools.ToolClamAV, Binary: binary, Args: []string{"--stdout", "--no-summary", abs}, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: 1 << 20},
		},
	}
	res, err := runner.Run(ctx, tools.Request{Tool: tools.ToolClamAV})
	if res.Warning == "nonzero_exit" {
		if strings.Contains(strings.Join(res.Notes, " | "), "exit_code: 1") {
			res.Warning = "threat_detected"
			res.Notes = append(res.Notes, "exit 1 is a detection result, not a scanner crash")
			res.Findings = 1
		} else {
			res.Warning = "scanner_error"
			res.Notes = append(res.Notes, "non-1 error exit is a scanner failure, not a clean host")
		}
	}
	return res, err
}

func approvedPath(abs string, roots []string) bool {
	for _, root := range roots {
		clean, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if abs == clean || strings.HasPrefix(abs, clean+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
