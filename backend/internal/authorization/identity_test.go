package authorization

import (
	"context"
	"os"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
)

func TestDirectoryRejectsAdminAndFiltersZones(t *testing.T) {
	raw, err := os.ReadFile("../../../examples/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := ParseDirectory(raw)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := dir.Lookup("operator-alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := operator.Can(ActionGrantApproval); err == nil {
		t.Fatal("operator granted approval")
	}
	auditor, err := dir.Lookup("auditor-carol")
	if err != nil {
		t.Fatal(err)
	}
	if err := auditor.Can(ActionRunFixture); err == nil {
		t.Fatal("auditor executed a scan")
	}
	if err := auditor.Can(ActionReadScan); err != nil {
		t.Fatal(err)
	}
	inv := twoZone(t)
	visible := operator.FilterHosts(inv.Authorized().Hosts)
	if len(visible) != 1 || visible[0].ID != "linux-test-001" {
		t.Fatalf("zone filter failed: %+v", visible)
	}
	if _, _, err := SelectFor(context.Background(), inv, operator, "linux-test-zone-b", "", "quick"); err == nil {
		t.Fatal("cross-zone host accepted")
	}
	foreign, err := dir.Lookup("operator-zone-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SelectFor(context.Background(), inv, foreign, "linux-test-001", "", "quick"); err == nil {
		t.Fatal("foreign zone operator selected host")
	}
	agent, err := operator.InheritAgent("agent-alice-1")
	if err != nil {
		t.Fatal(err)
	}
	if agent.InheritedFrom != operator.ID {
		t.Fatal("agent did not inherit caller")
	}
	if err := agent.Expand([]string{RoleApprover}, nil, nil); err == nil {
		t.Fatal("agent expanded privileges")
	}
	if _, err := agent.InheritAgent("agent-nested"); err == nil {
		t.Fatal("nested inherit accepted")
	}
	if err := dir.Revoke("operator-alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.Lookup("operator-alice"); err == nil {
		t.Fatal("revoked principal still visible")
	}
	if _, err := ParseDirectory([]byte(`{"schema_version":"1.0","note":"x","principals":[{"id":"admin-root","roles":["admin"],"zones":["test-zone-a"],"business_systems":["demo"]}]}`)); err == nil {
		t.Fatal("implicit admin accepted")
	}
}

func twoZone(t *testing.T) asset.Inventory {
	t.Helper()
	inv := inventory(t)
	ok := true
	extra := inv.Hosts[0]
	extra.ID = "linux-test-zone-b"
	extra.Hostname = "linux-test-zone-b"
	extra.Zone = "test-zone-b"
	extra.BusinessSystem = "other"
	extra.Authorized = &ok
	extra.Addresses = []string{"192.0.2.20"}
	inv.Hosts = append(inv.Hosts, extra)
	return inv
}
