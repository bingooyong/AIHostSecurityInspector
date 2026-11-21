package yara

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
	ErrRule    = errors.New("yara rule is not in the reviewed set or is unsafe")
	ErrScope   = errors.New("yara target is outside the approved file scope")
	ErrVersion = errors.New("yara version is not the pinned fixture version")
)

type Request struct {
	RulePath      string
	ReviewedDir   string
	Target        string
	ApprovedRoots []string
	Timeout       time.Duration
	LookPath      func(string) (string, error)
	Binary        string
	PinnedVersion string
}

func Run(ctx context.Context, req Request) (tools.Result, error) {
	if err := reviewRule(req.RulePath, req.ReviewedDir); err != nil {
		return tools.Result{Tool: tools.ToolYARA, Status: domain.CollectionFailed, Warning: "unsafe_rule"}, err
	}
	abs, err := filepath.Abs(req.Target)
	if err != nil {
		return tools.Result{}, err
	}
	if !allowedTarget(abs, req.ApprovedRoots) {
		return tools.Result{Tool: tools.ToolYARA, Status: domain.CollectionFailed, Warning: "scope"}, ErrScope
	}
	binary := req.Binary
	if binary == "" {
		binary = "yara"
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	args := []string{"--timeout", "1", req.RulePath, abs}
	runner := tools.Runner{
		LookPath: req.LookPath,
		Specs: map[string]tools.Spec{
			tools.ToolYARA: {Name: tools.ToolYARA, Binary: binary, Args: args, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: 1 << 20},
		},
	}
	res, err := runner.Run(ctx, tools.Request{Tool: tools.ToolYARA})
	if req.PinnedVersion != "" && !strings.Contains(strings.Join(res.Notes, "\n"), req.PinnedVersion) && res.Status == domain.CollectionSuccess {
		res.Status = domain.CollectionFailed
		res.Warning = "version_mismatch"
		return res, ErrVersion
	}
	return res, err
}

func reviewRule(rulePath, reviewedDir string) error {
	if rulePath == "" || reviewedDir == "" {
		return ErrRule
	}
	absRule, err := filepath.Abs(rulePath)
	if err != nil {
		return err
	}
	absDir, err := filepath.Abs(reviewedDir)
	if err != nil {
		return err
	}
	if absRule != absDir && !strings.HasPrefix(absRule, absDir+string(os.PathSeparator)) {
		return ErrRule
	}
	payload, err := os.ReadFile(absRule)
	if err != nil {
		return err
	}
	body := string(payload)
	lower := strings.ToLower(body)
	if strings.Contains(lower, "include") || strings.Contains(lower, "import") && strings.Contains(lower, "cuckoo") {
		return ErrRule
	}
	if strings.Contains(lower, "external") || strings.Contains(body, "extvar") {
		return ErrRule
	}
	return nil
}

func allowedTarget(abs string, roots []string) bool {
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
