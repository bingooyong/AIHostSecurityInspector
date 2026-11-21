package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/evidence"
)

func TestWriteJSONAndMarkdown(t *testing.T) {
	doc := Build("scan-fixture-001", "linux-test-001", domain.ProfileQuick, nil, []domain.RuleResult{{
		RuleID: "PROC-001", RuleVersion: "1.0", ScanID: "scan-fixture-001", HostID: "linux-test-001",
		Outcome: domain.OutcomeUnknown, EvidenceRefs: []string{}, MissingEvidence: []string{"process_inventory"}, ReasonCode: "missing_evidence",
	}}, nil, evidence.VerificationReport{Integrity: domain.IntegrityVerified, SourceAuthenticity: "unverified"}, []string{"fixture only"})
	dir := t.TempDir()
	path, err := Write(dir, doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "PROC-001 UNKNOWN") {
		t.Fatalf("%s", body)
	}
}

func TestReportIncludesRequiredItemsAndDoesNotLookSecureWhenIncomplete(t *testing.T) {
	doc := BuildFromInput(Input{
		ScanID: "scan-fixture-001", HostID: "linux-test-001", Profile: domain.ProfileQuick,
		Status: domain.JobCompleted, StartedAt: "2026-11-21T00:00:00Z", CompletedAt: "2026-11-21T00:00:02Z",
		CollectorVersion: "0.1.0", PolicyVersion: "1.0", RuleBundleVersion: "0.1.0",
		Modules: []collector.Result{
			{ModuleID: "host_identity", Status: domain.CollectionSuccess, StartedAt: "2026-11-21T00:00:00Z"},
			{ModuleID: "process_inventory", Status: domain.CollectionFailed, StartedAt: "2026-11-21T00:00:01Z"},
		},
		ExpectedModules: []string{"host_identity", "process_inventory", "network_inventory"},
		Evidence:        []domain.Evidence{sampleEvidence()},
		RuleResults: []domain.RuleResult{{
			RuleID: "PROC-001", RuleVersion: "1.0", ScanID: "scan-fixture-001", HostID: "linux-test-001",
			Outcome: domain.OutcomeUnknown, EvidenceRefs: []string{}, MissingEvidence: []string{"process_inventory"}, ReasonCode: "missing_evidence",
		}},
		Limitations: []string{"fixture only"},
		AIStatus:    domain.AIFailed,
		HumanReview: domain.HumanReview{Status: "pending", Notes: []string{"needs analyst review"}},
		Integrity:   evidence.VerificationReport{Integrity: domain.IntegrityUnverified, SourceAuthenticity: "unverified"},
	})
	if doc.Status != domain.JobPartial {
		t.Fatalf("incomplete scan stayed %s", doc.Status)
	}
	if doc.AIStatus != domain.AIFailed || doc.AIAssessment != nil {
		t.Fatalf("AI failure must still produce a deterministic report: %+v", doc)
	}
	if doc.CollectionSummary.TotalModules != 3 || doc.CollectionSummary.Succeeded != 1 || doc.CollectionSummary.Coverage == nil || *doc.CollectionSummary.Coverage >= 1 {
		t.Fatalf("coverage %+v", doc.CollectionSummary)
	}
	if len(doc.Uncovered) == 0 {
		t.Fatal("uncovered modules missing")
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range RequiredFields {
		if _, ok := raw[field]; !ok {
			t.Fatalf("missing required report field %s", field)
		}
	}
	if _, ok := raw["schema_version"]; !ok {
		t.Fatal("missing schema_version")
	}
	dir := t.TempDir()
	if _, err := Write(dir, doc); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, needle := range []string{"coverage denominator: 3", "## Uncovered", "process_inventory", "network_inventory", "## Human review", "pending", "## Evidence index", "evidence-process-1", "incomplete collection"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("markdown missing %q:\n%s", needle, text)
		}
	}
	if LooksSecure(doc, text) {
		t.Fatalf("incomplete report looks secure:\n%s", text)
	}
}

func TestMaliciousMarkdownIsNeutralized(t *testing.T) {
	doc := BuildFromInput(Input{
		ScanID: "scan-fixture-001", HostID: "linux-test-001", Profile: domain.ProfileQuick,
		Status: domain.JobPartial, StartedAt: "2026-11-21T00:00:00Z", CompletedAt: "2026-11-21T00:00:02Z",
		Limitations: []string{"```rm -rf /```\n# spoofed heading\n<script>alert(1)</script>"},
	})
	body := Markdown(doc)
	if strings.Contains(body, "```") || strings.Contains(body, "<script>") || strings.Contains(body, "\n# spoofed heading") {
		t.Fatalf("unsafe markdown survived:\n%s", body)
	}
}

func sampleEvidence() domain.Evidence {
	return domain.Evidence{
		EvidenceID: "evidence-process-1", HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		CollectedAt: "2026-11-21T00:00:00Z", ReceivedAt: "2026-11-21T00:00:01Z", Module: "process_inventory",
		CollectorVersion: "0.1.0", Category: "process", RawSummary: "process inventory",
		NormalizedData: map[string]any{}, CollectionStatus: domain.CollectionSuccess,
		IntegrityStatus: domain.IntegrityVerified, Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
}
