package linux

import (
	"context"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func packageReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModulePackageInventory, Profile: domain.ProfileStandard, PolicyVersion: "0.1.0",
	}
}

func TestPackageInventoryParsesDpkgWithoutInstalling(t *testing.T) {
	col := Packages{Root: fixtureRoot(t, "host"), Now: time.Now}
	result, err := col.Collect(context.Background(), packageReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	names := map[string]string{}
	for _, rec := range result.Records {
		names[rec["name"].(string)] = rec["version"].(string)
	}
	if names["libc6"] != "2.36-9" || names["openssh-server"] == "" {
		t.Fatalf("packages=%v", names)
	}
}

func TestPackageMissingDatabaseIsNotAvailable(t *testing.T) {
	col := Packages{Root: fixtureRoot(t, "partial"), Now: time.Now}
	result, err := col.Collect(context.Background(), packageReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotAvailable {
		t.Fatalf("status=%s", result.Status)
	}
}
