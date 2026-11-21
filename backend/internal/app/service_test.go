package app

import (
	"os"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
)

func TestListHostsFiltersDeniedAndForeignZone(t *testing.T) {
	inv, err := asset.Load(t.Context(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../../examples/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := authorization.ParseDirectory(raw)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(*inv, dir)
	alice, err := dir.Lookup("operator-alice")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := svc.ListAuthorizedHosts(t.Context(), alice, 20, 0)
	if err != nil || hosts.Total != 1 || len(hosts.Items) != 1 || hosts.Items[0].HostID != "linux-test-001" {
		t.Fatalf("alice hosts %+v %v", hosts, err)
	}
	page, err := svc.ListAuthorizedHosts(t.Context(), alice, 1, 1)
	if err != nil || page.Total != 1 || len(page.Items) != 0 {
		t.Fatalf("alice page %+v %v", page, err)
	}
	if _, err := svc.ListAuthorizedHosts(t.Context(), alice, 101, 0); err == nil {
		t.Fatal("limit above max accepted")
	}
	foreign, err := dir.Lookup("operator-zone-b")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err = svc.ListAuthorizedHosts(t.Context(), foreign, 20, 0)
	if err != nil || hosts.Total != 0 || len(hosts.Items) != 0 {
		t.Fatalf("foreign zone saw hosts %+v %v", hosts, err)
	}
}
