package findings

import (
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestUnknownDoesNotCreateFinding(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := domain.Evidence{
		EvidenceID: "evidence-process-1", HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		CollectedAt: "2026-11-21T00:00:00Z", ReceivedAt: "2026-11-21T00:00:01Z", Module: "process_inventory",
		CollectorVersion: "0.1.0", Category: "process", RawSummary: "process inventory",
		NormalizedData: map[string]any{}, SHA256: &hash, NormalizedSHA256: &hash,
		CollectionStatus: domain.CollectionSuccess, IntegrityStatus: domain.IntegrityVerified, Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
	unknown := domain.RuleResult{
		RuleID: "PROC-001", RuleVersion: "1.0", ScanID: "scan-fixture-001", HostID: "linux-test-001",
		Outcome: domain.OutcomeUnknown, EvidenceRefs: []string{}, MissingEvidence: []string{"process_inventory"}, ReasonCode: "missing_evidence",
	}
	got, err := FromRuleResults([]domain.RuleResult{unknown}, map[string]domain.Evidence{ev.EvidenceID: ev}, map[string]RuleMeta{"PROC-001": sampleMeta()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unknown created findings %+v", got)
	}
}

func TestFailRequiresUsableEvidence(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := domain.Evidence{
		EvidenceID: "evidence-process-1", HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		CollectedAt: "2026-11-21T00:00:00Z", ReceivedAt: "2026-11-21T00:00:01Z", Module: "process_inventory",
		CollectorVersion: "0.1.0", Category: "process", RawSummary: "process inventory",
		NormalizedData: map[string]any{}, SHA256: &hash, NormalizedSHA256: &hash,
		CollectionStatus: domain.CollectionSuccess, IntegrityStatus: domain.IntegrityUnverified, Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
	fail := domain.RuleResult{
		RuleID: "PROC-001", RuleVersion: "1.0", ScanID: "scan-fixture-001", HostID: "linux-test-001",
		Outcome: domain.OutcomeFail, EvidenceRefs: []string{ev.EvidenceID}, MissingEvidence: []string{}, ReasonCode: "deleted_executable",
	}
	_, err := FromRuleResults([]domain.RuleResult{fail}, map[string]domain.Evidence{ev.EvidenceID: ev}, map[string]RuleMeta{"PROC-001": sampleMeta()})
	if err == nil {
		t.Fatal("unverified evidence produced a finding")
	}
}

func sampleMeta() RuleMeta {
	return RuleMeta{Category: "process", Severity: domain.SeverityHigh, Confidence: 80, Title: "deleted executable", Description: "process executable is deleted", Remediation: []string{"investigate the process"}}
}

func TestFourOutcomesAndCrossScope(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := domain.Evidence{
		EvidenceID: "evidence-process-1", HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		CollectedAt: "2026-11-21T00:00:00Z", ReceivedAt: "2026-11-21T00:00:01Z", Module: "process_inventory",
		CollectorVersion: "0.1.0", Category: "process", RawSummary: "process inventory",
		NormalizedData: map[string]any{}, SHA256: &hash, NormalizedSHA256: &hash,
		CollectionStatus: domain.CollectionSuccess, IntegrityStatus: domain.IntegrityVerified, Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
	meta := map[string]RuleMeta{"PROC-001": sampleMeta()}
	for _, outcome := range []string{domain.OutcomePass, domain.OutcomeUnknown, domain.OutcomeNotApplicable} {
		got, err := FromRuleResults([]domain.RuleResult{{
			RuleID: "PROC-001", RuleVersion: "1.0", ScanID: "scan-fixture-001", HostID: "linux-test-001",
			Outcome: outcome, EvidenceRefs: []string{ev.EvidenceID},
		}}, map[string]domain.Evidence{ev.EvidenceID: ev}, meta)
		if err != nil {
			t.Fatalf("%s: %v", outcome, err)
		}
		if len(got) != 0 {
			t.Fatalf("%s created a finding", outcome)
		}
	}
	fail := domain.RuleResult{
		RuleID: "PROC-001", RuleVersion: "1.0", ScanID: "scan-fixture-001", HostID: "linux-test-001",
		Outcome: domain.OutcomeFail, EvidenceRefs: []string{ev.EvidenceID},
	}
	got, err := FromRuleResults([]domain.RuleResult{fail}, map[string]domain.Evidence{ev.EvidenceID: ev}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("usable FAIL should create a finding: %+v", got)
	}
	cross := ev
	cross.HostID = "linux-other-001"
	if _, err := FromRuleResults([]domain.RuleResult{fail}, map[string]domain.Evidence{cross.EvidenceID: cross}, meta); err == nil {
		t.Fatal("cross-host evidence accepted")
	}
	crossScan := ev
	crossScan.ScanID = "scan-other-001"
	if _, err := FromRuleResults([]domain.RuleResult{fail}, map[string]domain.Evidence{crossScan.EvidenceID: crossScan}, meta); err == nil {
		t.Fatal("cross-scan evidence accepted")
	}
}
