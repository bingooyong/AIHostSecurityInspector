package tools

import "context"

// Adapter is the typed readonly facade over Runner for the five approved tools.
type Adapter struct {
	Runner Runner
}

func (a Adapter) runner() Runner {
	if a.Runner.LookPath == nil && a.Runner.Specs == nil {
		return DefaultRunner()
	}
	return a.Runner
}

func (a Adapter) Osquery(ctx context.Context, req Request) (Result, error) {
	req.Tool = ToolOsquery
	return a.runner().Run(ctx, req)
}
func (a Adapter) Lynis(ctx context.Context, req Request) (Result, error) {
	req.Tool = ToolLynis
	return a.runner().Run(ctx, req)
}
func (a Adapter) OpenSCAP(ctx context.Context, req Request) (Result, error) {
	req.Tool = ToolOpenSCAP
	return a.runner().Run(ctx, req)
}
func (a Adapter) ClamAV(ctx context.Context, req Request) (Result, error) {
	req.Tool = ToolClamAV
	return a.runner().Run(ctx, req)
}
func (a Adapter) YARA(ctx context.Context, req Request) (Result, error) {
	req.Tool = ToolYARA
	return a.runner().Run(ctx, req)
}
