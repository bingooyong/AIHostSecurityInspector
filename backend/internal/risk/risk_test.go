package risk

import (
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestTrendAndReviewGuards(t *testing.T) {
	if err := LinkReview(Link{FindingID: "finding-1", Kind: KindFalsePositive, RelatedScanID: "scan-2", HostID: "linux-test-001"}); err != nil {
		t.Fatal(err)
	}
	if err := LinkReview(Link{FindingID: "finding-1", Kind: KindRemediation, RelatedScanID: "scan-2", HostID: "linux-test-001", Note: "auto"}); err == nil {
		t.Fatal("auto remediation accepted")
	}
	current := []domain.Finding{{FindingID: "finding-1", ScanID: "scan-1", HostID: "linux-test-001", RuleID: "PROC-001", ReviewStatus: domain.ReviewNew}}
	changes, err := Trend(nil, current, true)
	if err != nil || len(changes) != 0 {
		t.Fatal("first scan reported change", err, changes)
	}
	if _, err := Trend(current, current, true); err == nil {
		t.Fatal("first scan with previous accepted")
	}
	next := []domain.Finding{{FindingID: "finding-1", ScanID: "scan-2", HostID: "linux-test-001", RuleID: "PROC-001", ReviewStatus: domain.ReviewFalsePositive}}
	changes, err = Trend(current, next, false)
	if err != nil || len(changes) != 1 || changes[0].Kind != "review_status" {
		t.Fatal(err, changes)
	}
	drifted := []domain.Finding{{FindingID: "finding-1", ScanID: "scan-2", HostID: "linux-other", RuleID: "PROC-001", ReviewStatus: domain.ReviewNew}}
	changes, err = Trend(current, drifted, false)
	if err != nil || len(changes) != 2 {
		t.Fatal("host identity drift not surfaced", err, changes)
	}
}
