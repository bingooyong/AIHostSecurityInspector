package authorization

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAllowlistRejectsEmptyDuplicateAndUnknownFields(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadAllowlist(context.Background(), writeFile(t, dir, "empty.yaml", "version: 1\nhosts: []\n")); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	if _, err := LoadAllowlist(context.Background(), writeFile(t, dir, "dup.yaml", "version: 1\nhosts: [linux-box-lab-ssh-001, linux-box-lab-ssh-001]\n")); err == nil {
		t.Fatal("duplicate host accepted")
	}
	if _, err := LoadAllowlist(context.Background(), writeFile(t, dir, "unknown.yaml", "version: 1\nhosts: [linux-box-lab-ssh-001]\nextra: true\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
	got, err := LoadAllowlist(context.Background(), writeFile(t, dir, "ok.yaml", "version: 1\nprofile: quick\nhosts:\n  - linux-box-lab-ssh-001\n  - linux-box-lab-ssh-002\n"))
	if err != nil || len(got.Hosts) != 2 || got.Profile != "quick" {
		t.Fatalf("valid allowlist rejected: %+v %v", got, err)
	}
}

func TestLoadBindingsRequiresAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadBindings(context.Background(), writeFile(t, dir, "rel.yaml", "version: 1\nhosts:\n  - host_id: linux-box-lab-ssh-001\n    identity_path: id_ed25519\n    known_hosts_path: known_hosts\n")); err == nil {
		t.Fatal("relative binding paths accepted")
	}
}

func TestLoadBindingsAcceptsAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	identity := writeFile(t, dir, "id_ed25519", "fixture\n")
	known := writeFile(t, dir, "known_hosts", "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n")
	got, err := LoadBindings(context.Background(), writeFile(t, dir, "ok.yaml", "version: 1\nhosts:\n  - host_id: linux-box-lab-ssh-001\n    identity_path: "+identity+"\n    known_hosts_path: "+known+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].HostID != "linux-box-lab-ssh-001" {
		t.Fatalf("unexpected bindings: %+v", got)
	}
}
