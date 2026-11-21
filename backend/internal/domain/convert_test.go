package domain

import (
	"context"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
)

func TestHostRecordFromAssetMarksOSUnknown(t *testing.T) {
	inv, err := asset.Load(context.Background(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Hosts) == 0 {
		t.Fatal("expected fixture hosts")
	}
	record := HostRecordFromAsset(inv.Hosts[0])
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	if record.OSDistribution != OSUnknown || record.OSVersion != OSUnknown {
		t.Fatal("v1 assets must not pretend OS was collected")
	}
	if record.HostKeyPolicy != "strict" {
		t.Fatal("host key policy changed")
	}
}
