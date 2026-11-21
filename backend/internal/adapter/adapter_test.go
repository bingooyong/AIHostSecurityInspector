package adapter

import (
	"context"
	"os"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

func TestAdaptersDoNotInventCleanScans(t *testing.T) {
	exec := tools.Executor{Runner: &tools.Runner{LookPath: func(string) (string, error) { return "", os.ErrNotExist }, Specs: tools.DefaultSpecs()}}
	for _, fn := range []func(context.Context, tools.Executor, string, string) (Report, error){Osquery, Lynis, OpenSCAP, ClamAV, YARA} {
		report, err := fn(context.Background(), exec, "linux-test-001", "scan-fixture-001")
		if err != nil {
			t.Fatal(err)
		}
		if report.Result.Status != domain.CollectionNotAvailable {
			t.Fatalf("%s claimed %s", report.Name, report.Result.Status)
		}
	}
}
