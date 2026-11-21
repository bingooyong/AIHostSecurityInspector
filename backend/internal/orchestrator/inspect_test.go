package orchestrator

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestInspectFixtureRejectsLiveRootAndKeepsScanUnready(t *testing.T) {
	inv, err := asset.Load(context.Background(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = InspectFixture(context.Background(), Request{
		Root: "/", Inventory: *inv, HostID: "linux-test-001", Profile: domain.ProfileQuick, OutDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("live root accepted")
	}
}

func TestInspectFixtureQuickDoesNotMarkScanReady(t *testing.T) {
	inv, err := asset.Load(context.Background(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "collector", "linux", "testdata", "host"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := InspectFixture(context.Background(), Request{
		Root: root, Inventory: *inv, HostID: "linux-test-001", Profile: domain.ProfileQuick,
		OutDir: t.TempDir(), ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		Now: func() time.Time { return time.Date(2026, 11, 21, 2, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ScanReady || result.ExecutionReady || result.CollectorAvailable {
		t.Fatalf("readiness flags %+v", result)
	}
	if result.AIStatus != domain.AIDisabled {
		t.Fatalf("ai=%s", result.AIStatus)
	}
	if len(result.Modules) == 0 || len(result.RuleResults) != 9 {
		t.Fatalf("modules=%d rules=%d", len(result.Modules), len(result.RuleResults))
	}
	if result.ReportPath == "" {
		t.Fatal("missing report")
	}
}

func TestInspectFixtureRejectsDeepWithoutApproval(t *testing.T) {
	inv, err := asset.Load(context.Background(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "collector", "linux", "testdata", "host"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = InspectFixture(context.Background(), Request{
		Root: root, Inventory: *inv, HostID: "linux-test-001", Profile: domain.ProfileDeep, OutDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("deep profile accepted without approval")
	}
}
