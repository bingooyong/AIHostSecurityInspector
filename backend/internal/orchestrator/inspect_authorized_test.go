package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/transport/ssh"
)

func authorizedLabIntent(t *testing.T, inv asset.Inventory) domain.ExecutionIntent {
	t.Helper()
	intent, err := planner.BuildIntent(context.Background(), inv, planner.IntentRequest{
		Targets: "group:lab-ssh-pair", Profile: "quick", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-21T00:00:00Z", ValidUntil: "2026-11-21T04:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func labSSHBindings(t *testing.T) authorization.CollectionBindings {
	t.Helper()
	inv := labInventory(t)
	dir := t.TempDir()
	out := authorization.CollectionBindings{Version: 1}
	for _, host := range inv.Hosts {
		if host.ID != "linux-box-lab-ssh-001" && host.ID != "linux-box-lab-ssh-002" {
			continue
		}
		pattern := "[" + host.Addresses[0] + "]:" + strconv.Itoa(host.Connection.Port)
		out.Hosts = append(out.Hosts, authorization.HostBinding{
			HostID:         host.ID,
			IdentityPath:   writeTempFile(t, dir, host.ID+"-id", "fixture-not-a-real-ssh-identity\n"),
			KnownHostsPath: writeTempFile(t, dir, host.ID+"-known", pattern+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n"),
		})
	}
	return out
}

func writeTempFile(t *testing.T, dir, name, body string) string {
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

func TestInspectAuthorizedRefusesBeforeConnecting(t *testing.T) {
	inv := labInventory(t)
	allowlist := authorization.CollectionAllowlist{Version: 1, Profile: "quick", Hosts: []string{"linux-box-lab-denied"}}
	_, err := InspectAuthorized(context.Background(), AuthorizedRequest{
		Inventory: inv, Allowlist: allowlist, Intent: authorizedLabIntent(t, inv),
		Profile: "quick", OutDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("unauthorized allowlist accepted")
	}
	docs, err := asset.Load(context.Background(), filepath.Join("..", "..", "..", "examples", "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	docIntent, err := planner.BuildIntent(context.Background(), *docs, planner.IntentRequest{
		HostID: "linux-test-001", Profile: "quick", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-21T00:00:00Z", ValidUntil: "2026-11-21T04:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = InspectAuthorized(context.Background(), AuthorizedRequest{
		Inventory: *docs, Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-test-001"}},
		Intent: docIntent, Profile: "quick", OutDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("non-loopback documentation host accepted")
	}
}

func TestInspectAuthorizedRequiresOutputDirectory(t *testing.T) {
	inv := labInventory(t)
	_, err := InspectAuthorized(context.Background(), AuthorizedRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  labSSHBindings(t), Intent: authorizedLabIntent(t, inv), Profile: "quick",
	})
	if err == nil {
		t.Fatal("missing output directory accepted")
	}
}

func TestInspectAuthorizedCancelDoesNotCollect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := InspectAuthorized(ctx, AuthorizedRequest{OutDir: t.TempDir()})
	if err == nil {
		t.Fatal("cancelled authorized inspect succeeded")
	}
}

func TestInspectAuthorizedLiveMultiHostSSH(t *testing.T) {
	if os.Getenv("HOSTSEC_LIVE_SSH_MULTI") != "1" {
		t.Skip("set HOSTSEC_LIVE_SSH_MULTI=1 to run the two-listener authorized collection test")
	}
	inv := labInventory(t)
	bindings := authorization.CollectionBindings{Version: 1, Hosts: []authorization.HostBinding{
		liveBinding(t, "linux-box-lab-ssh-001", "HOSTSEC_LIVE_SSH_001"),
		liveBinding(t, "linux-box-lab-ssh-002", "HOSTSEC_LIVE_SSH_002"),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out := t.TempDir()
	result, err := InspectAuthorized(ctx, AuthorizedRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Profile: "quick", Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  bindings, Intent: authorizedLabIntent(t, inv), Profile: "quick", OutDir: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		t.Fatalf("product flags set: %+v", result)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("hosts=%d", len(result.Hosts))
	}
	seen := map[string]int{}
	for _, host := range result.Hosts {
		if host.CollectorAvailable || host.ScanReady || host.ExecutionReady {
			t.Fatalf("per-host product flags set: %+v", host)
		}
		if host.JobStatus == domain.JobCompleted {
			t.Fatal("lab inspect completed as a production PASS")
		}
		if len(host.Modules) == 0 || host.ReportPath == "" {
			t.Fatalf("incomplete host result: %+v", host)
		}
		seen[host.HostID] = 1
	}
	if seen["linux-box-lab-ssh-001"] != 1 || seen["linux-box-lab-ssh-002"] != 1 {
		t.Fatalf("unexpected hosts: %v", seen)
	}
	// Cross-binding: host 001 must not accept host 002's known_hosts.
	cross := bindings
	cross.Hosts = []authorization.HostBinding{
		{HostID: "linux-box-lab-ssh-001", IdentityPath: bindings.Hosts[0].IdentityPath, KnownHostsPath: bindings.Hosts[1].KnownHostsPath},
		bindings.Hosts[1],
	}
	_, err = InspectAuthorized(ctx, AuthorizedRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  cross, Intent: authorizedLabIntent(t, inv), Profile: "quick", OutDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("cross-host known_hosts binding accepted")
	}
	_ = ssh.ErrKnownHostsBinding
}

func liveBinding(t *testing.T, hostID, prefix string) authorization.HostBinding {
	t.Helper()
	identity := os.Getenv(prefix + "_IDENTITY")
	known := os.Getenv(prefix + "_KNOWN_HOSTS")
	if identity == "" || known == "" {
		t.Fatalf("%s_IDENTITY and %s_KNOWN_HOSTS are required", prefix, prefix)
	}
	return authorization.HostBinding{HostID: hostID, IdentityPath: identity, KnownHostsPath: known}
}
