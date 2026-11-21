package analyzer

import (
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestRejectsCitationOutsideView(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := domain.Evidence{
		EvidenceID: "evidence-process-1", HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-1",
		CollectedAt: "2026-11-21T00:00:00Z", ReceivedAt: "2026-11-21T00:00:01Z", Module: "process_inventory",
		CollectorVersion: "0.1.0", Category: "process", RawSummary: "process", NormalizedData: map[string]any{},
		SHA256: &hash, NormalizedSHA256: &hash, CollectionStatus: domain.CollectionSuccess,
		IntegrityStatus: domain.IntegrityVerified, Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
	assessment := domain.Assessment{
		AssessmentID: "assessment-1", HostID: "linux-test-001", ScanID: "scan-fixture-001",
		Provider: "none", Model: "none", PromptVersion: "0", OverallAssessment: domain.AssessmentInsufficient,
		RiskLevel: domain.SeverityInfo, Facts: []domain.Fact{}, Inferences: []domain.Fact{},
		EvidenceRefs: []string{"evidence-secret-1"}, RequiresHumanReview: true,
	}
	err := ValidateCitations(View{EvidenceIDs: []string{"evidence-process-1"}}, assessment, map[string]domain.Evidence{ev.EvidenceID: ev})
	if err == nil {
		t.Fatal("out-of-view citation accepted")
	}
}
