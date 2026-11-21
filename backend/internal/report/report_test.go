package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
