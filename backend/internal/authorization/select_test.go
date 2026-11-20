package authorization

import (
	"context"
	"os"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
)

func inventory(t *testing.T) asset.Inventory {
	t.Helper()
	b, err := os.ReadFile("../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := asset.Parse(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	return *inv
}

func TestSelectRejectsMixedGroupAndIP(t *testing.T) {
	inv := inventory(t)
	if _, _, err := Select(context.Background(), inv, "", "group:mixed", "quick"); err == nil {
		t.Fatal("mixed group accepted")
	}
	if _, _, err := Select(context.Background(), inv, "192.0.2.10", "", "quick"); err == nil {
		t.Fatal("IP identity accepted")
	}
	hosts, profile, err := Select(context.Background(), inv, "linux-test-001", "", "quick")
	if err != nil || len(hosts) != 1 || profile.Name != "quick" {
		t.Fatal(err, hosts, profile)
	}
}
