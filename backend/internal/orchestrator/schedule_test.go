package orchestrator

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "collector", "linux", "testdata", "host"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func fixtureInv(t *testing.T) asset.Inventory {
	t.Helper()
	inv, err := asset.Load(context.Background(), filepath.Join("..", "..", "..", "examples", "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return *inv
}

func TestPSISourceHighAndOkFixtures(t *testing.T) {
	high, err := filepath.Abs(filepath.Join("testdata", "pressure-high"))
	if err != nil {
		t.Fatal(err)
	}
	stressed, reason, err := (PSISource{Dir: high, Avg10Limit: 20}).Stressed()
	if err != nil || !stressed || reason == "" {
		t.Fatalf("high pressure: stressed=%v reason=%s err=%v", stressed, reason, err)
	}
	ok, err := filepath.Abs(filepath.Join("testdata", "pressure-ok"))
	if err != nil {
		t.Fatal(err)
	}
	stressed, _, err = (PSISource{Dir: ok, Avg10Limit: 20}).Stressed()
	if err != nil || stressed {
		t.Fatalf("ok pressure: stressed=%v err=%v", stressed, err)
	}
}

func TestInspectFixturePressureStopDoesNotPass(t *testing.T) {
	inv := fixtureInv(t)
	result, err := InspectFixture(context.Background(), Request{
		Root: fixtureRoot(t), Inventory: inv, HostID: "linux-test-001", Profile: domain.ProfileQuick,
		OutDir: t.TempDir(), ScanID: "scan-pressure-001", AttemptID: "attempt-pressure-001",
		Now:      func() time.Time { return time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC) },
		Pressure: &SequencePressure{After: 1, Reason: "lab cpu pressure"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ScanReady || result.CollectorAvailable || result.ExecutionReady {
		t.Fatalf("product flags: %+v", result)
	}
	if result.JobStatus == domain.JobCompleted || result.JobStatus == domain.JobCreated {
		t.Fatalf("pressure stop completed as success: %s", result.JobStatus)
	}
	stopped := 0
	for _, module := range result.Modules {
		for _, warning := range module.Warnings {
			if warning == "resource_pressure_stop" {
				stopped++
			}
		}
		if module.Status == domain.CollectionFailed && module.ErrorCode == "" {
			t.Fatalf("failed module missing code: %+v", module)
		}
	}
	if stopped == 0 {
		t.Fatalf("pressure did not stop remaining modules: %+v", result.Modules)
	}
	for _, rule := range result.RuleResults {
		if rule.Outcome == domain.OutcomePass {
			t.Fatalf("pressure/collection failure still PASS: %+v", rule)
		}
	}
}

func TestRunAuthorizedCancelAndDriftDoNotComplete(t *testing.T) {
	inv := fixtureInv(t)
	jobs := NewJobStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job, result, err := RunAuthorized(ctx, jobs, Job{ScanID: "scan-fx-cancel", HostID: "linux-test-001", Profile: domain.ProfileQuick, Owner: "operator-alice"}, Request{
		Root: fixtureRoot(t), Inventory: inv, HostID: "linux-test-001", Profile: domain.ProfileQuick,
		OutDir: t.TempDir(), ScanID: "scan-fx-cancel",
	}, false)
	if err == nil {
		t.Fatal("cancelled fixture run succeeded")
	}
	if job.Status == domain.JobCompleted || result.JobStatus == domain.JobCompleted {
		t.Fatalf("cancel completed: job=%s result=%s", job.Status, result.JobStatus)
	}

	hash, err := asset.HashSnapshot(inv)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := policy.CurrentHash(domain.ProfileQuick)
	if err != nil {
		t.Fatal(err)
	}
	drifted := inv
	drifted.Hosts = append([]asset.Host{}, inv.Hosts...)
	falseVal := false
	host := drifted.Hosts[0]
	host.Authorized = &falseVal
	drifted.Hosts[0] = host
	jobs = NewJobStore()
	job, result, err = RunAuthorized(context.Background(), jobs, Job{ScanID: "scan-fx-drift", HostID: "linux-test-001", Profile: domain.ProfileQuick, Owner: "operator-alice"}, Request{
		Root: fixtureRoot(t), Inventory: drifted, HostID: "linux-test-001", Profile: domain.ProfileQuick,
		OutDir: t.TempDir(), ScanID: "scan-fx-drift", SnapshotHash: hash, PolicyHash: policyHash,
	}, false)
	if err == nil {
		t.Fatal("authorization drift accepted")
	}
	if job.Status != domain.JobRejected && job.Status != domain.JobFailed {
		t.Fatalf("drift status=%s", job.Status)
	}
	if result.JobStatus == domain.JobCompleted {
		t.Fatal("drift completed as PASS")
	}
}

func TestRunAuthorizedFixturePressureAttemptDoesNotPass(t *testing.T) {
	inv := fixtureInv(t)
	jobs := NewJobStore()
	job, result, err := RunAuthorized(context.Background(), jobs, Job{ScanID: "scan-fx-pressure", HostID: "linux-test-001", Profile: domain.ProfileQuick, Owner: "operator-alice"}, Request{
		Root: fixtureRoot(t), Inventory: inv, HostID: "linux-test-001", Profile: domain.ProfileQuick,
		OutDir: t.TempDir(), ScanID: "scan-fx-pressure", AttemptID: "attempt-1",
		Now:      func() time.Time { return time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC) },
		Pressure: &SequencePressure{After: 0, Reason: "pressure at start"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status == domain.JobCompleted || result.JobStatus == domain.JobCompleted || result.ScanReady {
		t.Fatalf("pressure run completed: job=%s result=%s", job.Status, result.JobStatus)
	}
	for _, rule := range result.RuleResults {
		if rule.Outcome == domain.OutcomePass {
			t.Fatalf("pressure attempt PASS: %+v", rule)
		}
	}
	// A later attempt is a new job; a prior failure must not be rewritten to COMPLETED.
	first, err := jobs.Get("scan-fx-pressure")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status == domain.JobCompleted {
		t.Fatal("stored job became COMPLETED")
	}
}

func TestRunAuthorizedPolicyHashDriftRejected(t *testing.T) {
	inv := fixtureInv(t)
	jobs := NewJobStore()
	job, _, err := RunAuthorized(context.Background(), jobs, Job{ScanID: "scan-fx-policy", HostID: "linux-test-001", Profile: domain.ProfileQuick, Owner: "operator-alice"}, Request{
		Root: fixtureRoot(t), Inventory: inv, HostID: "linux-test-001", Profile: domain.ProfileQuick,
		OutDir: t.TempDir(), ScanID: "scan-fx-policy",
		PolicyHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}, false)
	if err == nil || job.Status != domain.JobRejected {
		t.Fatalf("policy drift: status=%s err=%v", job.Status, err)
	}
}
