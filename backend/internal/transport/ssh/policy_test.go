package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyRejectsRootAndArbitraryExec(t *testing.T) {
	path := writeKnownHosts(t, "linux-test-001 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxx\n")
	err := Validate(Policy{User: "root", Port: 22, KnownHostsPath: path, HostKeyPolicy: "strict", AllowedBinary: "hostsec-collector"})
	if err == nil {
		t.Fatal("root accepted")
	}
	err = Validate(Policy{User: "hostsec-audit", Port: 22, KnownHostsPath: path, HostKeyPolicy: "accept-new", AllowedBinary: "hostsec-collector"})
	if err != ErrInsecurePolicy {
		t.Fatalf("insecure policy: %v", err)
	}
	err = Validate(Policy{User: "hostsec-audit", Port: 22, KnownHostsPath: path, HostKeyPolicy: "strict", AllowedBinary: "bash", AllowedArgs: []string{"-c", "id"}})
	if err != ErrArbitraryExec {
		t.Fatalf("arbitrary exec: %v", err)
	}
}

func TestKnownHostsWildcardRejected(t *testing.T) {
	path := writeKnownHosts(t, "* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxx\n")
	if err := ValidateKnownHosts(path); err != ErrKnownHosts {
		t.Fatalf("wildcard accepted: %v", err)
	}
}

func TestFixedCollectorCommand(t *testing.T) {
	path := writeKnownHosts(t, "linux-test-001 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxx\n")
	args, err := CommandLine(Policy{User: "hostsec-audit", Port: 22, KnownHostsPath: path, HostKeyPolicy: "strict", AllowedBinary: "hostsec-collector", AllowedArgs: []string{"collect", "--module", "host_identity"}})
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "hostsec-collector" {
		t.Fatalf("%v", args)
	}
}

func writeKnownHosts(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
