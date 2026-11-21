package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func writeKnown(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHostKeyPatternRejectsNonLoopback(t *testing.T) {
	if _, err := HostKeyPattern("192.0.2.10", 22); err == nil {
		t.Fatal("documentation address accepted")
	}
	if _, err := HostKeyPattern("127.0.0.1", 0); err == nil {
		t.Fatal("invalid port accepted")
	}
	got, err := HostKeyPattern("127.0.0.1", 2222)
	if err != nil || got != "[127.0.0.1]:2222" {
		t.Fatalf("got %q %v", got, err)
	}
	got, err = HostKeyPattern("::1", 2223)
	if err != nil || got != "[::1]:2223" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestKnownHostsCoversExactLoopbackTarget(t *testing.T) {
	path := writeKnown(t, "known_hosts", "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n")
	if err := KnownHostsCovers(path, "127.0.0.1", 2222); err != nil {
		t.Fatal(err)
	}
	if err := KnownHostsCovers(path, "127.0.0.1", 2223); err == nil {
		t.Fatal("wrong port accepted")
	}
	if err := KnownHostsCovers(path, "::1", 2222); err == nil {
		t.Fatal("wrong address accepted")
	}
}

func TestKnownHostsCoversPort22BareAddress(t *testing.T) {
	path := writeKnown(t, "known_hosts", "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n")
	if err := KnownHostsCovers(path, "127.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
}

func TestKnownHostsCoversRejectsWildcardAndHashed(t *testing.T) {
	if err := KnownHostsCovers(writeKnown(t, "wild", "* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n"), "127.0.0.1", 2222); err == nil {
		t.Fatal("wildcard accepted")
	}
	hashed := writeKnown(t, "hashed", "|1|aaaaaaaaaaaaaaaaaaaaaaaaaaa=|bbbbbbbbbbbbbbbbbbbbbbbbbbb= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n")
	if err := KnownHostsCovers(hashed, "127.0.0.1", 2222); err == nil {
		t.Fatal("hashed entry accepted as a literal binding")
	}
}

func TestKnownHostsCoversRejectsNonLoopbackAddress(t *testing.T) {
	path := writeKnown(t, "known_hosts", "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n")
	if err := KnownHostsCovers(path, "192.0.2.10", 22); err == nil {
		t.Fatal("non-loopback address accepted")
	}
}
