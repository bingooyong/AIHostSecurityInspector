package orchestrator

import (
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestJobStoreRejectsSkipAndCompletedReady(t *testing.T) {
	store := NewJobStore()
	job, err := store.Create(Job{ScanID: "scan-fixture-job", HostID: "linux-test-001", Profile: "quick", Owner: "operator-alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Advance(job.ScanID, domain.JobCompleted); err == nil {
		t.Fatal("CREATED jumped to COMPLETED")
	}
	path := []string{domain.JobValidating, domain.JobQueued, domain.JobRunning, domain.JobCollecting, domain.JobNormalizing, domain.JobRuleEvaluation, domain.JobPartial}
	for _, next := range path {
		if _, err := store.Advance(job.ScanID, next); err != nil {
			t.Fatal(next, err)
		}
	}
	got, err := store.Get(job.ScanID)
	if err != nil || got.Status != domain.JobPartial || got.ScanReady || got.CollectorReady {
		t.Fatalf("fixture job claimed live completion: %+v", got)
	}
	again, err := store.Create(Job{ScanID: "scan-other", HostID: "linux-test-001", Profile: "quick", Owner: "operator-alice", IdempotencyKey: "idem-1"})
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := store.Create(Job{ScanID: "scan-other-2", HostID: "linux-test-001", Profile: "quick", Owner: "operator-alice", IdempotencyKey: "idem-1"})
	if err != nil || repeat.ScanID != again.ScanID {
		t.Fatal("idempotency failed", err, repeat)
	}
	found, ok := store.LookupByKey("operator-alice", "idem-1")
	if !ok || found.ScanID != again.ScanID {
		t.Fatalf("lookup missed stored key: %+v", found)
	}
	if listed := store.List(); len(listed) != 2 {
		t.Fatalf("list: %+v", listed)
	}
}
