package asset

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotHashStableAndSensitive(t *testing.T) {
	inv, err := Parse(context.Background(), sample(t))
	if err != nil {
		t.Fatal(err)
	}
	a, err := HashSnapshot(*inv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashSnapshot(*inv)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("hash unstable")
	}
	golden := filepath.Join("testdata", "asset-snapshot.sha256")
	if _, err := os.Stat(golden); err != nil {
		if writeErr := os.MkdirAll("testdata", 0o755); writeErr != nil {
			t.Fatal(writeErr)
		}
		if writeErr := os.WriteFile(golden, []byte(a+"\n"), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		t.Fatalf("wrote snapshot golden %s; re-run", a)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if a != string(bytes.TrimSpace(want)) {
		t.Fatalf("snapshot hash drifted: %s vs %s", a, string(want))
	}
	clone := *inv
	clone.Hosts = append([]Host{}, inv.Hosts...)
	authorized := false
	h := clone.Hosts[0]
	h.Authorized = &authorized
	clone.Hosts[0] = h
	changed, err := HashSnapshot(clone)
	if err != nil {
		t.Fatal(err)
	}
	if changed == a {
		t.Fatal("authorization change did not affect snapshot")
	}
	if err := Revalidate(a, *inv); err != nil {
		t.Fatal(err)
	}
	if err := Revalidate(a, clone); err == nil {
		t.Fatal("drift accepted")
	}
}

func TestDiffDetectsSecurityFields(t *testing.T) {
	inv, err := Parse(context.Background(), sample(t))
	if err != nil {
		t.Fatal(err)
	}
	next := *inv
	next.Hosts = append([]Host{}, inv.Hosts...)
	h := next.Hosts[0]
	h.Connection.KnownHostsRef = "known-hosts:other"
	h.Addresses = []string{"192.0.2.99"}
	next.Hosts[0] = h
	diff, err := DiffInventories(*inv, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.ChangedHosts) != 1 {
		t.Fatalf("expected host change, got %#v", diff)
	}
	foundAddr, foundKeys := false, false
	for _, change := range diff.ChangedHosts[0].Changes {
		if change.Field == "addresses" {
			foundAddr = true
		}
		if change.Field == "known_hosts_ref" {
			foundKeys = true
		}
		if change.Field == "auth_ref" && change.To != h.Connection.AuthRef {
			t.Fatal("diff leaked unexpected auth material")
		}
	}
	if !foundAddr || !foundKeys {
		t.Fatalf("missing security field changes: %#v", diff.ChangedHosts[0].Changes)
	}
}

func TestSnapshotOrderIndependence(t *testing.T) {
	inv, err := Parse(context.Background(), sample(t))
	if err != nil {
		t.Fatal(err)
	}
	reversed := *inv
	reversed.Hosts = []Host{inv.Hosts[1], inv.Hosts[0]}
	a, err := HashSnapshot(*inv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashSnapshot(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("host order changed snapshot hash")
	}
}
