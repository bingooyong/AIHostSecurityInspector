package analyzer

import (
	"context"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestAIDisabledByDefault(t *testing.T) {
	res, err := (Provider{}).Enrich(context.Background(), View{ScanID: "scan-fixture-001", HostID: "linux-test-001"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.AIDisabled || res.Assessment != nil {
		t.Fatalf("%+v", res)
	}
}

func TestMinimizeKeepsOnlyAllowedIDs(t *testing.T) {
	view := Minimize([]domain.Finding{{FindingID: "finding-PROC-001-1"}}, []string{"evidence-process-1"})
	if len(view.EvidenceIDs) != 1 || view.EvidenceIDs[0] != "evidence-process-1" {
		t.Fatalf("%+v", view)
	}
}
