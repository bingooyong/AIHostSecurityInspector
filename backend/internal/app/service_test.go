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
	hosts, err := svc.ListAuthorizedHosts(t.Context(), alice)
	if err != nil || len(hosts) != 1 || hosts[0].ID != "linux-test-001" {
		t.Fatalf("alice hosts %+v %v", hosts, err)
	}
	foreign, err := dir.Lookup("operator-zone-b")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err = svc.ListAuthorizedHosts(t.Context(), foreign)
	if err != nil || len(hosts) != 0 {
		t.Fatalf("foreign zone saw hosts %+v %v", hosts, err)
	}
}
