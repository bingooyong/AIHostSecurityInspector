package domain

import "testing"

func TestValidateSnapshotAcceptsFixture(t *testing.T) {
	if err := ValidateSnapshot(validSnapshot()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSnapshotRejectsCrossScopeAndUnusableEvidence(t *testing.T) {
	t.Run("cross-host evidence", func(t *testing.T) {
		snap := validSnapshot()
		ev := snap.Evidence[0]
		ev.HostID = "linux-other-001"
		snap.Evidence[0] = ev
		if err := ValidateSnapshot(snap); err == nil {
			t.Fatal("expected cross-scope failure")
		} else if de, ok := err.(*Error); !ok || de.Code != CodeCrossScopeReference {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("duplicate evidence", func(t *testing.T) {
		snap := validSnapshot()
		snap.Evidence = append(snap.Evidence, snap.Evidence[0])
		if err := ValidateSnapshot(snap); err == nil {
			t.Fatal("expected duplicate")
		}
	})
	t.Run("failed evidence cannot PASS", func(t *testing.T) {
		snap := validSnapshot()
		snap.Evidence = []Evidence{failedEvidence()}
		snap.RuleResults[0].EvidenceRefs = []string{"ev-failed-1"}
		if err := ValidateSnapshot(snap); err == nil {
			t.Fatal("PASS with failed evidence")
		} else if de, ok := err.(*Error); !ok || de.Code != CodeEvidenceUnusable {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("finding without evidence", func(t *testing.T) {
		snap := validSnapshot()
		snap.Findings[0].EvidenceRefs = nil
		if err := ValidateSnapshot(snap); err == nil {
			t.Fatal("empty finding refs")
		}
	})
	t.Run("unknown evidence", func(t *testing.T) {
		snap := validSnapshot()
		snap.Findings[0].EvidenceRefs = []string{"ev-missing"}
		if err := ValidateSnapshot(snap); err == nil {
			t.Fatal("unknown evidence accepted")
		} else if de, ok := err.(*Error); !ok || de.Code != CodeUnknownEvidence {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no-change without baseline", func(t *testing.T) {
		snap := validSnapshot()
		snap.RuleResults[0].ReasonCode = "NO_CHANGE"
		if err := ValidateSnapshot(snap); err == nil {
			t.Fatal("no-change without baseline")
		} else if de, ok := err.(*Error); !ok || de.Code != CodeMissingBaseline {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("collection failure finding", func(t *testing.T) {
		snap := validSnapshot()
		failEv := failedEvidence()
		snap.Evidence = append(snap.Evidence, failEv)
		snap.Findings = []Finding{{
			FindingID:           "finding-collect-1",
			ScanID:              "scan-demo-1",
			HostID:              "linux-test-001",
			RuleID:              "COLLECT-001",
			RuleVersion:         "1.0",
			Category:            CategoryCollectionFailure,
			Severity:            SeverityInfo,
			Confidence:          100,
			Title:               "collection failed",
			Description:         "module failed",
			EvidenceRefs:        []string{"ev-failed-1"},
			RemediationGuidance: []string{},
			RequiresHumanReview: true,
			ReviewStatus:        ReviewNew,
		}}
		if err := ValidateSnapshot(snap); err != nil {
			t.Fatal(err)
		}
	})
}

func TestValidateAssessmentAllowedSetAndSeverity(t *testing.T) {
	snap := validSnapshot()
	snap.Job.AIStatus = AISuccess
	snap.Job.Status = JobCompleted
	assessment := Assessment{
		AssessmentID:        "assess-1",
		HostID:              "linux-test-001",
		ScanID:              "scan-demo-1",
		Provider:            "fake",
		Model:               "local-fixture",
		PromptVersion:       "1.0",
		OverallAssessment:   AssessmentSuspicious,
		Confidence:          40,
		RiskLevel:           SeverityLow,
		Facts:               []Fact{{Statement: "process inventory exists", EvidenceRefs: []string{"ev-process-1"}}},
		Inferences:          []Fact{{Statement: "needs review", EvidenceRefs: []string{"ev-process-1"}}},
		EvidenceRefs:        []string{"ev-process-1"},
		MissingEvidence:     []string{},
		RecommendedActions:  []string{"review"},
		Limitations:         []string{"fixture"},
		RequiresHumanReview: true,
	}
	snap.Assessment = &assessment
	if err := ValidateSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	snap.AllowedEvidenceIDs = []string{"ev-other"}
	if err := ValidateSnapshot(snap); err == nil {
		t.Fatal("assessment used evidence outside allowed set")
	}
}

func TestRuleUnknownWithoutPASS(t *testing.T) {
	result := RuleResult{
		RuleID: "PROC-001", RuleVersion: "1.0", ScanID: "scan-demo-1", HostID: "linux-test-001",
		Outcome: OutcomeUnknown, EvidenceRefs: []string{}, MissingEvidence: []string{"process list"}, ReasonCode: "NOT_COLLECTED",
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	result.Outcome = OutcomePass
	if err := result.Validate(); err == nil {
		t.Fatal("PASS without evidence")
	}
}
