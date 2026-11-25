package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
)

func fixtureKnownHosts(t *testing.T, dir, name, pattern string) string {
	t.Helper()
	return writeTempFile(t, dir, name, pattern+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxxxx\n")
}

func fixtureIdentity(t *testing.T, dir, name string) string {
	t.Helper()
	return writeTempFile(t, dir, name, "fixture-not-a-real-ssh-identity\n")
}

func validIntent(t *testing.T, inv asset.Inventory, targets, profile string) domain.ExecutionIntent {
	t.Helper()
	intent, err := planner.BuildIntent(context.Background(), inv, planner.IntentRequest{
		Targets: targets, Profile: profile, RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-21T00:00:00Z", ValidUntil: "2026-11-21T04:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func sshBindingsFor(t *testing.T, dir string, hosts []asset.Host) authorization.CollectionBindings {
	t.Helper()
	out := authorization.CollectionBindings{Version: 1}
	for _, host := range hosts {
		if host.Connection.Transport != "ssh" {
			continue
		}
		entry := "[" + host.Addresses[0] + "]:" + strconv.Itoa(host.Connection.Port)
		if host.Connection.Port == 22 {
			entry = host.Addresses[0]
		}
		out.Hosts = append(out.Hosts, authorization.HostBinding{
			HostID:         host.ID,
			IdentityPath:   fixtureIdentity(t, dir, host.ID+"/id_ed25519"),
			KnownHostsPath: fixtureKnownHosts(t, dir, host.ID+"/known_hosts", entry),
		})
	}
	return out
}

func pairHosts(inv asset.Inventory) []asset.Host {
	var hosts []asset.Host
	for _, item := range inv.Hosts {
		if item.ID == "linux-box-lab-ssh-001" || item.ID == "linux-box-lab-ssh-002" {
			hosts = append(hosts, item)
		}
	}
	return hosts
}

func TestPrepareAuthorizedCollectionAcceptsAllowlistedLoopbackSSH(t *testing.T) {
	inv := labInventory(t)
	dir := t.TempDir()
	allowlist := authorization.CollectionAllowlist{Version: 1, Profile: "quick", Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}}
	prepared, err := PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv, Allowlist: allowlist, Bindings: sshBindingsFor(t, dir, pairHosts(inv)),
		Intent: validIntent(t, inv, "group:lab-ssh-pair", "quick"), Profile: "quick",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 2 {
		t.Fatalf("hosts=%d", len(prepared))
	}
	if prepared[0].SSH == nil || prepared[1].SSH == nil {
		t.Fatal("SSH bindings missing")
	}
	if prepared[0].SSH.Policy.Port == prepared[1].SSH.Policy.Port {
		t.Fatal("distinct lab hosts must keep distinct ports")
	}
}

func TestPrepareAuthorizedCollectionRefusesUnauthorizedUnknownAndNonLoopback(t *testing.T) {
	inv := labInventory(t)
	intent := validIntent(t, inv, "group:lab-ssh-pair", "quick")
	_, err := PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv, Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-denied"}},
		Intent: intent, Profile: "quick",
	})
	if err == nil {
		t.Fatal("unauthorized host accepted")
	}
	_, err = PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv, Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-missing-001"}},
		Intent: intent, Profile: "quick",
	})
	if err == nil {
		t.Fatal("unknown host accepted")
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
	_, err = PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: *docs, Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-test-001"}},
		Intent: docIntent, Profile: "quick",
	})
	if err == nil {
		t.Fatal("documentation/non-loopback address accepted")
	}
}

func TestPrepareAuthorizedCollectionRequiresIntentAndAllowlistToMatch(t *testing.T) {
	inv := labInventory(t)
	dir := t.TempDir()
	bindings := sshBindingsFor(t, dir, pairHosts(inv))
	intent := validIntent(t, inv, "group:lab-ssh-pair", "quick")
	_, err := PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv, Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001"}},
		Bindings: bindings, Intent: intent, Profile: "quick",
	})
	if err == nil {
		t.Fatal("subset allowlist accepted against a two-host intent")
	}
	_, err = PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv, Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-unlisted"}},
		Bindings: bindings, Intent: intent, Profile: "quick",
	})
	if err == nil {
		t.Fatal("allowlist with an authorized but unlisted host accepted against the intent")
	}
}

func TestPrepareAuthorizedCollectionRefusesCrossHostKnownHosts(t *testing.T) {
	inv := labInventory(t)
	dir := t.TempDir()
	var first, second asset.Host
	for _, item := range inv.Hosts {
		switch item.ID {
		case "linux-box-lab-ssh-001":
			first = item
		case "linux-box-lab-ssh-002":
			second = item
		}
	}
	bindings := authorization.CollectionBindings{Version: 1, Hosts: []authorization.HostBinding{
		{HostID: first.ID, IdentityPath: fixtureIdentity(t, dir, "a/id"), KnownHostsPath: fixtureKnownHosts(t, dir, "a/known", "[127.0.0.1]:2223")},
		{HostID: second.ID, IdentityPath: fixtureIdentity(t, dir, "b/id"), KnownHostsPath: fixtureKnownHosts(t, dir, "b/known", "[127.0.0.1]:2223")},
	}}
	_, err := PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv, Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings: bindings, Intent: validIntent(t, inv, "group:lab-ssh-pair", "quick"), Profile: "quick",
	})
	if err == nil {
		t.Fatal("host 001 accepted a known_hosts entry for port 2223")
	}
}

func TestPrepareAuthorizedCollectionRefusesDeepProfile(t *testing.T) {
	inv := labInventory(t)
	allowlist := authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}}
	_, err := PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv, Allowlist: allowlist, Intent: domain.ExecutionIntent{Profile: "deep"}, Profile: "deep",
	})
	if err == nil {
		t.Fatal("deep profile accepted")
	}
}

func TestPrepareAuthorizedCollectionIgnoresAuthorizedHostOffAllowlist(t *testing.T) {
	inv := labInventory(t)
	dir := t.TempDir()
	prepared, err := PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  sshBindingsFor(t, dir, pairHosts(inv)),
		Intent:    validIntent(t, inv, "group:lab-ssh-pair", "quick"),
		Profile:   "quick",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range prepared {
		if item.Host.ID == "linux-box-lab-ssh-unlisted" || item.Host.ID == "linux-box-lab-001" {
			t.Fatalf("collected a host that was not allowlisted: %s", item.Host.ID)
		}
	}
}

func TestCancelledPrepareStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PrepareAuthorizedCollection(ctx, CollectionPlanRequest{})
	if err == nil {
		t.Fatal("cancelled prepare succeeded")
	}
}

func TestPrepareAuthorizedCollectionRejectsMissingSSHBindingFiles(t *testing.T) {
	inv := labInventory(t)
	bindings := authorization.CollectionBindings{Version: 1, Hosts: []authorization.HostBinding{
		{HostID: "linux-box-lab-ssh-001", IdentityPath: "/tmp/hostsec-missing-id", KnownHostsPath: "/tmp/hostsec-missing-known"},
		{HostID: "linux-box-lab-ssh-002", IdentityPath: "/tmp/hostsec-missing-id-2", KnownHostsPath: "/tmp/hostsec-missing-known-2"},
	}}
	_, err := PrepareAuthorizedCollection(context.Background(), CollectionPlanRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  bindings, Intent: validIntent(t, inv, "group:lab-ssh-pair", "quick"), Profile: "quick",
	})
	if err == nil {
		t.Fatal("missing SSH binding files accepted")
	}
	_ = os.ErrNotExist
}
