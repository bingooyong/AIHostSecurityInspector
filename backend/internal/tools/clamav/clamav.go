package clamav

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
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
	SignaturesDir   string
	Now             time.Time
	Timeout         time.Duration
	LookPath        func(string) (string, error)
	Binary          string
	ExtraArgs       []string
}

type Result struct {
	tools.Result
	SideEffects []string `json:"side_effects"`
}

func Run(ctx context.Context, req Request) (Result, error) {
	for _, arg := range req.ExtraArgs {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "remove") || strings.Contains(lower, "move") || strings.Contains(lower, "copy") || strings.Contains(lower, "delete") {
			return Result{Result: tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "mutation_forbidden"}}, ErrMutation
		}
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	if req.SignaturesDir != "" {
		until, err := signatureExpiry(req.SignaturesDir)
		if err != nil {
			return Result{Result: tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "stale_signatures", Notes: []string{"signature database is missing"}}}, ErrSignatures
		}
		if req.SignaturesUntil.IsZero() || until.Before(req.SignaturesUntil) {
			req.SignaturesUntil = until
		}
	}
	if req.SignaturesUntil.IsZero() || now.After(req.SignaturesUntil) {
		return Result{Result: tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "stale_signatures", Notes: []string{"signature database is stale; missing intel cannot be a clean scan"}}}, ErrSignatures
	}
	abs, err := filepath.Abs(req.Path)
	if err != nil {
		return Result{}, err
	}
	if !approvedPath(abs, req.ApprovedRoots) {
		return Result{Result: tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "path_not_approved"}}, ErrPath
	}
	if _, err := os.Stat(abs); err != nil {
		return Result{Result: tools.Result{Tool: tools.ToolClamAV, Status: domain.CollectionFailed, Warning: "path_missing"}}, err
	}
	binary := req.Binary
	if binary == "" {
		binary = "clamscan"
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	args := []string{"--stdout", "--no-summary"}
	if req.SignaturesDir != "" {
		args = append(args, "--database", req.SignaturesDir)
	}
	args = append(args, abs)
	before, _ := snapshotPath(abs)
	look := req.LookPath
	if look == nil {
		look = tools.LookPathWithFallbacks(nil, []string{"/usr/bin/clamscan"})
	}
	runner := tools.Runner{
		LookPath: look,
		Specs: map[string]tools.Spec{
			tools.ToolClamAV: {Name: tools.ToolClamAV, Binary: binary, Args: args, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: 1 << 20},
		},
	}
	res, err := runner.Run(ctx, tools.Request{Tool: tools.ToolClamAV})
	after, _ := snapshotPath(abs)
	out := Result{Result: res, SideEffects: pathDiff(before, after)}
	if len(out.SideEffects) > 0 {
		out.Notes = append(out.Notes, "scan path changed: "+strings.Join(out.SideEffects, ", "))
	}
	if out.Warning == "nonzero_exit" {
		if strings.Contains(strings.Join(out.Notes, " | "), "exit_code: 1") {
			out.Warning = "threat_detected"
			out.Notes = append(out.Notes, "exit 1 is a detection result, not a scanner crash")
			out.Findings = 1
		} else {
			out.Warning = "scanner_error"
			out.Notes = append(out.Notes, "non-1 error exit is a scanner failure, not a clean host")
		}
	}
	return out, err
}

func signatureExpiry(dir string) (time.Time, error) {
	var newest time.Time
	found := false
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, err
	}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".cvd") && !strings.HasSuffix(name, ".cld") && !strings.HasSuffix(name, ".cud") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		found = true
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if !found {
		return time.Time{}, ErrSignatures
	}
	// Official CVD files older than 14 days are treated as stale for this adapter.
	return newest.Add(14 * 24 * time.Hour), nil
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

func snapshotPath(path string) (map[string]os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return map[string]os.FileInfo{path: info}, nil
}

func pathDiff(before, after map[string]os.FileInfo) []string {
	if before == nil || after == nil {
		return nil
	}
	var out []string
	for name, afterInfo := range after {
		beforeInfo, ok := before[name]
		if !ok {
			out = append(out, name+" added")
			continue
		}
		if afterInfo.Size() != beforeInfo.Size() || afterInfo.Mode() != beforeInfo.Mode() {
			out = append(out, name+" mutated")
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			out = append(out, name+" removed")
		}
	}
	sort.Strings(out)
	return out
}
