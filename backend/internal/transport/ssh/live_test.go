package ssh

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLiveOpenSSHCollector exercises a real OpenSSH sshd bound to loopback.
// It is skipped unless HOSTSEC_LIVE_SSH=1 and the lab environment variables are set.
func TestLiveOpenSSHCollector(t *testing.T) {
	if os.Getenv("HOSTSEC_LIVE_SSH") != "1" {
		t.Skip("set HOSTSEC_LIVE_SSH=1 to run the real OpenSSH lab test")
	}
	identity := os.Getenv("HOSTSEC_LIVE_SSH_IDENTITY")
	known := os.Getenv("HOSTSEC_LIVE_SSH_KNOWN_HOSTS")
	user := os.Getenv("HOSTSEC_LIVE_SSH_USER")
	addr := os.Getenv("HOSTSEC_LIVE_SSH_ADDRESS")
	portRaw := os.Getenv("HOSTSEC_LIVE_SSH_PORT")
	if identity == "" || known == "" || user == "" || portRaw == "" {
		t.Fatal("HOSTSEC_LIVE_SSH_IDENTITY, HOSTSEC_LIVE_SSH_KNOWN_HOSTS, HOSTSEC_LIVE_SSH_USER and HOSTSEC_LIVE_SSH_PORT are required")
	}
	if addr == "" {
		addr = "127.0.0.1"
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		t.Fatal(err)
	}
	args, err := BuildCollectorArgs("host_identity", "scan-lab-001", "attempt-lab-001", "linux-box-lab-ssh-001", "quick", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := DialConfig{
		Address:      addr,
		IdentityPath: identity,
		Timeout:      20 * time.Second,
		Policy: Policy{
			User: user, Port: port, KnownHostsPath: known, HostKeyPolicy: "strict",
			AllowedBinary: CollectorBinary, AllowedArgs: args,
		},
	}
	out, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("invalid collector json: %s", out)
	}
	status, _ := payload["status"].(string)
	if status != "success" && status != "partial" {
		t.Fatalf("live ssh collect status=%v body=%s", payload["status"], out)
	}
	raw := strings.ToLower(string(out))
	if strings.Contains(raw, "-----begin") || strings.Contains(raw, "private key") {
		t.Fatal("live ssh output contained private key material")
	}
}

func TestLiveOpenSSHHostKeyMismatchRejected(t *testing.T) {
	if os.Getenv("HOSTSEC_LIVE_SSH") != "1" {
		t.Skip("set HOSTSEC_LIVE_SSH=1 to run the real OpenSSH lab test")
	}
	known := os.Getenv("HOSTSEC_LIVE_SSH_KNOWN_HOSTS")
	identity := os.Getenv("HOSTSEC_LIVE_SSH_IDENTITY")
	user := os.Getenv("HOSTSEC_LIVE_SSH_USER")
	portRaw := os.Getenv("HOSTSEC_LIVE_SSH_PORT")
	if known == "" || identity == "" || user == "" || portRaw == "" {
		t.Fatal("live ssh environment is incomplete")
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		t.Fatal(err)
	}
	wrong := writeTemp(t, "known_hosts_wrong", "[127.0.0.1]:"+portRaw+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n")
	args, err := BuildCollectorArgs("host_identity", "scan-lab-001", "attempt-lab-001", "linux-box-lab-ssh-001", "quick", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := DialConfig{
		Address: "127.0.0.1", IdentityPath: identity, Timeout: 5 * time.Second,
		Policy: Policy{User: user, Port: port, KnownHostsPath: wrong, HostKeyPolicy: "strict", AllowedBinary: CollectorBinary, AllowedArgs: args},
	}
	_, err = Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("mismatched known_hosts accepted against live sshd")
	}
	_ = known
}
