package tools

import (
	"context"
	"sort"
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
	// Output is bounded stdout for adapters that must parse tool results.
	// It is omitted from JSON so default reports do not leak host identity.
	Output string `json:"-"`
}

var catalog = map[string]bool{
	ToolOsquery: true, ToolLynis: true, ToolOpenSCAP: true, ToolClamAV: true, ToolYARA: true,
}

type Executor struct {
	Runner *Runner
}

func (e Executor) Run(ctx context.Context, req Request) (Result, error) {
	runner := DefaultRunner()
	if e.Runner != nil {
		runner = *e.Runner
	}
	return runner.Run(ctx, req)
}

func Known() []string {
	out := make([]string, 0, len(catalog))
	for name := range catalog {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
