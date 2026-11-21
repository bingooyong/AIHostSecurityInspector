package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func labInventory(t *testing.T) asset.Inventory {
	t.Helper()
	inv, err := asset.Load(context.Background(), filepath.Join("..", "..", "..", "examples", "lab-localhost.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return *inv
}

func TestInspectLocalRejectsNonLoopbackAndUnauthorized(t *testing.T) {
	inv, err := asset.Load(context.Background(), filepath.Join("..", "..", "..", "examples", "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = InspectLocal(context.Background(), Request{Inventory: *inv, HostID: "linux-test-001", Profile: domain.ProfileQuick, OutDir: t.TempDir()})
	if err == nil {
		t.Fatal("documentation address accepted as live target")
	}
	lab := labInventory(t)
	_, err = InspectLocal(context.Background(), Request{Inventory: lab, HostID: "linux-box-lab-denied", Profile: domain.ProfileQuick, OutDir: t.TempDir()})
	if err == nil {
		t.Fatal("unauthorized loopback host accepted")
	}
}

func TestInspectLocalCollectsAuthorizedLoopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live inspect requires linux")
	}
	out := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := InspectLocal(ctx, Request{
		Inventory: labInventory(t), HostID: "linux-box-lab-001", Profile: domain.ProfileQuick,
		OutDir: out, ScanID: "scan-lab-001", AttemptID: "attempt-lab-001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		t.Fatalf("product flags set: %+v", result)
	}
	if result.JobStatus == domain.JobCompleted {
		t.Fatal("lab inspect completed as a production PASS")
	}
	if len(result.Modules) == 0 || result.ReportPath == "" {
		t.Fatalf("modules=%d report=%s", len(result.Modules), result.ReportPath)
	}
	if _, err := os.Stat(filepath.Join(out, "hostsec.sqlite")); err != nil {
		t.Fatal("sqlite evidence was not persisted")
	}
}

func TestRunAuthorizedCancelDoesNotComplete(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live inspect requires linux")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	jobs := NewJobStore()
	job, result, err := RunAuthorized(ctx, jobs, Job{ScanID: "scan-lab-cancel", HostID: "linux-box-lab-001", Profile: domain.ProfileQuick, Owner: "operator-alice"}, Request{
		Inventory: labInventory(t), HostID: "linux-box-lab-001", Profile: domain.ProfileQuick, OutDir: t.TempDir(), ScanID: "scan-lab-cancel",
	}, true)
	if err == nil {
		t.Fatal("cancelled run succeeded")
	}
	if job.Status == domain.JobCompleted || result.JobStatus == domain.JobCompleted {
		t.Fatalf("cancel became completed: job=%+v result=%s", job, result.JobStatus)
	}
}

func TestRunAuthorizedFixtureFailureDoesNotPass(t *testing.T) {
	inv, err := asset.Load(context.Background(), filepath.Join("..", "..", "..", "examples", "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	jobs := NewJobStore()
	job, result, err := RunAuthorized(context.Background(), jobs, Job{ScanID: "scan-fx-fail", HostID: "linux-test-001", Profile: domain.ProfileQuick, Owner: "operator-alice"}, Request{
		Root: "/", Inventory: *inv, HostID: "linux-test-001", Profile: domain.ProfileQuick, OutDir: t.TempDir(), ScanID: "scan-fx-fail",
	}, false)
	if err == nil {
		t.Fatal("live root fixture inspect succeeded")
	}
	if job.Status == domain.JobCompleted || result.JobStatus == domain.JobCompleted {
		t.Fatalf("failure became PASS/COMPLETED: job=%+v", job)
	}
}
