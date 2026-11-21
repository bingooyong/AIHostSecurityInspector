package risk

import (
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestClosedLoopRescanAndHostDrift(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	finding := domain.Finding{FindingID: "finding-1", ScanID: "scan-1", HostID: "linux-test-001", RuleID: "PROC-001", ReviewStatus: domain.ReviewNew}
	cs, err := store.OpenCase(finding, now)
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != StateOpen {
		t.Fatalf("state=%s", cs.State)
	}
	if _, err := store.LinkRescan(cs.CaseID, "scan-2", "linux-test-001", false, now.Add(time.Hour)); err != ErrClosedLoop {
		t.Fatalf("verified without remediation: %v", err)
	}
	if _, err := store.RecordRemediation(cs.CaseID, "auto", "scan-1", "patched", now.Add(time.Minute)); err != ErrAutoTraining {
		t.Fatalf("auto actor accepted: %v", err)
	}
	if _, err := store.RecordRemediation(cs.CaseID, "operator-alice", "scan-1", "train", now.Add(time.Minute)); err != ErrAutoTraining {
		t.Fatalf("train note accepted: %v", err)
	}
	cs, err = store.RecordRemediation(cs.CaseID, "operator-alice", "scan-1", "package updated by operator", now.Add(time.Minute))
	if err != nil || cs.State != StateRemediated {
		t.Fatalf("remediation: %+v %v", cs, err)
	}
	if _, err := store.LinkRescan(cs.CaseID, "scan-2", "linux-other-001", false, now.Add(2*time.Hour)); err != ErrHostDrift {
		t.Fatalf("host drift closed the case: %v", err)
	}
	cs, err = store.LinkRescan(cs.CaseID, "scan-2", "linux-test-001", false, now.Add(2*time.Hour))
	if err != nil || cs.State != StateVerified {
		t.Fatalf("expected verified: %+v %v", cs, err)
	}
	cs, err = store.LinkRescan(cs.CaseID, "scan-3", "linux-test-001", true, now.Add(3*time.Hour))
	if err != nil || cs.State != StateReopened {
		t.Fatalf("expected reopened: %+v %v", cs, err)
	}
	timeline, err := store.Timeline(cs.CaseID)
	if err != nil || len(timeline) < 4 {
		t.Fatalf("timeline=%+v %v", timeline, err)
	}
	if timeline[0].Action != "open" || timeline[len(timeline)-1].State != StateReopened {
		t.Fatalf("time series=%+v", timeline)
	}

	series, err := Series("linux-test-001", [][]domain.Finding{
		{finding},
		{{FindingID: "finding-1", ScanID: "scan-2", HostID: "linux-test-001", RuleID: "PROC-001", ReviewStatus: domain.ReviewNew}},
		{},
	})
	if err != nil {
		t.Fatal(err)
	}
	absent := false
	for _, change := range series {
		if change.Kind == "absent" {
			absent = true
		}
	}
	if !absent {
		t.Fatalf("series missing closed-loop absence: %+v", series)
	}
	if _, err := Series("linux-test-001", [][]domain.Finding{
		{finding},
		{{FindingID: "finding-1", ScanID: "scan-2", HostID: "linux-other-001", RuleID: "PROC-001"}},
	}); err != ErrHostDrift {
		t.Fatalf("series host drift: %v", err)
	}
}

func TestFalsePositiveIsHumanOnly(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	cs, err := store.OpenCase(domain.Finding{FindingID: "finding-2", ScanID: "scan-1", HostID: "linux-test-001", RuleID: "NET-001"}, now)
	if err != nil {
		t.Fatal(err)
	}
	cs, err = store.RecordFalsePositive(cs.CaseID, "operator-alice", "scan-1", now.Add(time.Minute))
	if err != nil || cs.State != StateFalsePositive {
		t.Fatalf("%+v %v", cs, err)
	}
	if err := LinkReview(Link{FindingID: "finding-2", Kind: KindFalsePositive, RelatedScanID: "scan-1", HostID: "linux-test-001"}); err != nil {
		t.Fatal(err)
	}
}
