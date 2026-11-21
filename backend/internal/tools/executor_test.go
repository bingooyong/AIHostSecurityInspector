package tools

import (
	"context"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestExecutorDoesNotClaimCleanWhenMissing(t *testing.T) {
	res, err := (Executor{}).Run(context.Background(), Request{Tool: ToolClamAV, HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.CollectionNotAvailable || res.Findings != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestUnknownToolRejected(t *testing.T) {
	res, err := (Executor{}).Run(context.Background(), Request{Tool: "bash", HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.CollectionFailed || res.Warning != "unknown_tool" {
		t.Fatalf("%+v", res)
	}
}
