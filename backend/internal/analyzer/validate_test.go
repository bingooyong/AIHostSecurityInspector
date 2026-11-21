package analyzer

import (
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestValidateAssessmentRejectsCrossHostAndFiction(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := domain.Evidence{
		EvidenceID: "evidence-1", HostID: "linux-test-001", ScanID: "scan-1", AttemptID: "attempt-1",
		CollectedAt: "2026-11-21T00:00:00Z", ReceivedAt: "2026-11-21T00:00:01Z", Module: "process_inventory",
		CollectorVersion: "0.1.0", Category: "process", RawSummary: "process", NormalizedData: map[string]any{},
		SHA256: &hash, NormalizedSHA256: &hash, CollectionStatus: domain.CollectionSuccess,
		IntegrityStatus: domain.IntegrityVerified, Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
	view := View{ScanID: "scan-1", HostID: "linux-test-001", EvidenceIDs: []string{"evidence-1"}}
	ok := domain.Assessment{
		AssessmentID: "assessment-1", HostID: "linux-test-001", ScanID: "scan-1",
		Provider: "none", Model: "none", PromptVersion: "1.0", OverallAssessment: domain.AssessmentSuspicious,
		RiskLevel: domain.SeverityHigh, Facts: []domain.Fact{{Statement: "fact", EvidenceRefs: []string{"evidence-1"}}},
		Inferences: []domain.Fact{}, EvidenceRefs: []string{"evidence-1"}, MissingEvidence: []string{},
		RecommendedActions: []string{}, Limitations: []string{"lab"}, RequiresHumanReview: true,
	}
	if err := ValidateAssessment(view, ok, map[string]domain.Evidence{ev.EvidenceID: ev}); err != nil {
		t.Fatal(err)
	}
	fiction := ok
	fiction.EvidenceRefs = []string{"evidence-fictional"}
	if err := ValidateAssessment(view, fiction, map[string]domain.Evidence{ev.EvidenceID: ev}); err == nil {
		t.Fatal("fictional evidence accepted")
	}
	cross := ev
	cross.HostID = "linux-other-001"
	polluted := ok
	if err := ValidateAssessment(view, polluted, map[string]domain.Evidence{ev.EvidenceID: cross}); err == nil {
		t.Fatal("cross-host evidence accepted")
	}
	missing := ok
	missing.EvidenceRefs = nil
	missing.MissingEvidence = nil
	if err := ValidateAssessment(view, missing, map[string]domain.Evidence{ev.EvidenceID: ev}); err == nil {
		t.Fatal("empty refs accepted")
	}
	wrongScan := ok
	wrongScan.ScanID = "scan-other"
	if err := ValidateAssessment(view, wrongScan, map[string]domain.Evidence{ev.EvidenceID: ev}); err == nil {
		t.Fatal("cross-scan assessment accepted")
	}
}
