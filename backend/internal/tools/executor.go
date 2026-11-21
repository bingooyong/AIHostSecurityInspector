package tools

import (
	"context"
	"sort"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const (
	ToolOsquery  = "osquery"
	ToolLynis    = "lynis"
	ToolOpenSCAP = "openscap"
	ToolClamAV   = "clamav"
	ToolYARA     = "yara"
)

type Request struct {
	Tool    string
	HostID  string
	ScanID  string
	Profile string
}

type Result struct {
	Tool     string   `json:"tool"`
	Status   string   `json:"status"`
	Warning  string   `json:"warning"`
	Findings int      `json:"findings"`
	Notes    []string `json:"notes"`
}

var catalog = map[string]bool{
	ToolOsquery: true, ToolLynis: true, ToolOpenSCAP: true, ToolClamAV: true, ToolYARA: true,
}

type Executor struct{}

func (Executor) Run(ctx context.Context, req Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !catalog[req.Tool] {
		return Result{Tool: req.Tool, Status: domain.CollectionFailed, Warning: "unknown_tool", Notes: []string{"refusing arbitrary tool execution"}}, nil
	}
	return Result{
		Tool: req.Tool, Status: domain.CollectionNotAvailable, Warning: "tool_not_installed", Findings: 0,
		Notes: []string{"readonly executor does not spawn host tools in this slice", "missing tool cannot be reported as a clean scan"},
	}, nil
}

func Known() []string {
	out := make([]string, 0, len(catalog))
	for name := range catalog {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
