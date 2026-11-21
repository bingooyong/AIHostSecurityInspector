package adapter

import (
	"context"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

type Report struct {
	Name   string       `json:"name"`
	Result tools.Result `json:"result"`
}

func Osquery(ctx context.Context, exec tools.Executor, hostID, scanID string) (Report, error) {
	return run(ctx, exec, tools.ToolOsquery, hostID, scanID)
}
func Lynis(ctx context.Context, exec tools.Executor, hostID, scanID string) (Report, error) {
	return run(ctx, exec, tools.ToolLynis, hostID, scanID)
}
func OpenSCAP(ctx context.Context, exec tools.Executor, hostID, scanID string) (Report, error) {
	return run(ctx, exec, tools.ToolOpenSCAP, hostID, scanID)
}
func ClamAV(ctx context.Context, exec tools.Executor, hostID, scanID string) (Report, error) {
	return run(ctx, exec, tools.ToolClamAV, hostID, scanID)
}
func YARA(ctx context.Context, exec tools.Executor, hostID, scanID string) (Report, error) {
	return run(ctx, exec, tools.ToolYARA, hostID, scanID)
}

func run(ctx context.Context, exec tools.Executor, tool, hostID, scanID string) (Report, error) {
	result, err := exec.Run(ctx, tools.Request{Tool: tool, HostID: hostID, ScanID: scanID})
	return Report{Name: tool, Result: result}, err
}
