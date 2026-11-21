package lynis

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestLynisWritesOnlyControlledReportDirAndMissingTool(t *testing.T) {
	bin, err := filepath.Abs(filepath.Join("testdata", "lynis"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	res, err := Run(context.Background(), Request{
		ReportDir: dir, ApprovedItems: []string{"SSH-001", "FILE-001"}, Timeout: 3 * time.Second,
		Binary: "lynis", LookPath: func(string) (string, error) { return bin, nil },
	})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("%+v %v", res, err)
	}
	if len(res.SideEffects) == 0 || res.ReportPath == "" {
		t.Fatalf("side effects not disclosed: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "lynis-report.dat")); err != nil {
		t.Fatal(err)
	}
	res, err = Run(context.Background(), Request{ReportDir: t.TempDir(), Binary: "lynis", LookPath: func(string) (string, error) { return "", os.ErrNotExist }})
	if err != nil || res.Status != domain.CollectionNotAvailable {
		t.Fatalf("missing: %+v %v", res, err)
	}
}
