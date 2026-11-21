package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
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

func TestLabJobStatusNeverCompletesAndExplainsPartial(t *testing.T) {
	status, reason := labJobStatus(nil)
	if status != domain.JobFailed || reason == "" {
		t.Fatalf("empty modules: %s %s", status, reason)
	}
	success := []collector.Result{{ModuleID: "host_identity", Status: domain.CollectionSuccess}, {ModuleID: "process_inventory", Status: domain.CollectionSuccess}}
	status, reason = labJobStatus(success)
	if status != domain.JobPartial || !strings.Contains(reason, "all lab modules collected successfully") {
		t.Fatalf("success status=%s reason=%s", status, reason)
	}
	mixed := []collector.Result{{ModuleID: "host_identity", Status: domain.CollectionSuccess}, {ModuleID: "process_inventory", Status: domain.CollectionPartial}}
	status, reason = labJobStatus(mixed)
	if status != domain.JobPartial || !strings.Contains(reason, "incomplete") {
		t.Fatalf("mixed status=%s reason=%s", status, reason)
	}
}

func TestInspectAuthorizedIntentLedgerRejectsReplay(t *testing.T) {
	inv := labInventory(t)
	dir := t.TempDir()
	ledger, err := approval.OpenLedger(filepath.Join(dir, "intent-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	req := AuthorizedRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Profile: "quick", Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  labSSHBindings(t), Intent: authorizedLabIntent(t, inv), Profile: "quick",
		IntentLedger: ledger, OutDir: filepath.Join(dir, "out-1"),
		Pressure: &SequencePressure{After: 0, Reason: "stop before collect"},
	}
	result, err := InspectAuthorized(context.Background(), req)
	if err == nil {
		t.Fatal("pressure stop returned success")
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		t.Fatalf("product flags set: %+v", result)
	}
	if result.JobStatus == domain.JobCompleted {
		t.Fatal("pressure stop completed as a production PASS")
	}
	if result.ReportPath == "" {
		t.Fatal("pressure stop did not write an aggregate report")
	}
	if _, statErr := os.Stat(result.ReportPath); statErr != nil {
		t.Fatal(statErr)
	}
	report, readErr := os.ReadFile(result.ReportPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	body := string(report)
	if !strings.Contains(body, `"collector_available": false`) || !strings.Contains(body, `"job_status"`) {
		t.Fatalf("aggregate report missing required fields: %s", body)
	}
	if strings.Contains(body, `"evidence"`) || strings.Contains(body, `"hosts":`) {
		t.Fatalf("aggregate report must not embed raw hosts or evidence: %s", body)
	}
	if len(result.HostSummaries) != 2 {
		t.Fatalf("summaries=%d", len(result.HostSummaries))
	}
	for _, summary := range result.HostSummaries {
		if summary.Collected {
			t.Fatalf("host collected after pressure stop: %+v", summary)
		}
	}
	req.OutDir = filepath.Join(dir, "out-2")
	_, err = InspectAuthorized(context.Background(), req)
	if err == nil {
		t.Fatal("replayed intent accepted")
	}
	if !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("replay error: %v", err)
	}
}

func TestInspectAuthorizedPressureKeepsFirstHostWhenLiveLinux(t *testing.T) {
	if os.Getenv("HOSTSEC_LIVE_LINUX") != "1" {
		t.Skip("set HOSTSEC_LIVE_LINUX=1 to collect the authorized local lab host")
	}
	inv := labInventory(t)
	intent, err := planner.BuildIntent(context.Background(), inv, planner.IntentRequest{
		HostID: "linux-box-lab-001", Profile: "quick", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-21T00:00:00Z", ValidUntil: "2026-11-21T04:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Build a two-host local inventory so the second host can be skipped after the first collects.
	second := inv
	var first asset.Host
	for _, host := range inv.Hosts {
		if host.ID == "linux-box-lab-001" {
			first = host
			break
		}
	}
	duplicate := first
	duplicate.ID = "linux-box-lab-003"
	duplicate.Hostname = "linux-box-lab-003"
	second.Hosts = []asset.Host{first, duplicate}
	second.Groups = map[string]asset.Group{"lab-local-pair": {Hosts: []string{"linux-box-lab-001", "linux-box-lab-003"}}}
	// Re-load is safer than hand-editing hashes; skip if inventory validation rejects the synthetic pair.
	if err := second.Validate(); err != nil {
		t.Skip("synthetic two-host local inventory is not valid in this fixture: " + err.Error())
	}
	pairIntent, err := planner.BuildIntent(context.Background(), second, planner.IntentRequest{
		Targets: "group:lab-local-pair", Profile: "quick", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-21T00:00:00Z", ValidUntil: "2026-11-21T04:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = intent
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out := t.TempDir()
	result, err := InspectAuthorized(ctx, AuthorizedRequest{
		Inventory: second,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Profile: "quick", Hosts: []string{"linux-box-lab-001", "linux-box-lab-003"}},
		Intent:    pairIntent, Profile: "quick", OutDir: out,
		Pressure: &SequencePressure{After: 1, Reason: "stop after first host"},
	})
	if err == nil {
		t.Fatal("pressure after first host returned success")
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		t.Fatalf("product flags set: %+v", result)
	}
	if result.JobStatus == domain.JobCompleted {
		t.Fatal("partial pressure job completed as a production PASS")
	}
	if result.ReportPath == "" {
		t.Fatal("missing aggregate report")
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("hosts=%d", len(result.Hosts))
	}
	if result.Hosts[0].HostID != "linux-box-lab-001" || result.Hosts[0].ReportPath == "" {
		t.Fatalf("first host was not kept: %+v", result.Hosts[0])
	}
	if result.Hosts[1].HostID != "linux-box-lab-003" || result.Hosts[1].ReportPath != "" {
		t.Fatalf("second host should have been skipped: %+v", result.Hosts[1])
	}
}

func TestInspectAuthorizedLiveMultiHostWritesReportAndRejectsReplay(t *testing.T) {
	if os.Getenv("HOSTSEC_LIVE_SSH_MULTI") != "1" {
		t.Skip("set HOSTSEC_LIVE_SSH_MULTI=1 to run the two-listener authorized collection test")
	}
	inv := labInventory(t)
	bindings := authorization.CollectionBindings{Version: 1, Hosts: []authorization.HostBinding{
		liveBinding(t, "linux-box-lab-ssh-001", "HOSTSEC_LIVE_SSH_001"),
		liveBinding(t, "linux-box-lab-ssh-002", "HOSTSEC_LIVE_SSH_002"),
	}}
	dir := t.TempDir()
	ledger, err := approval.OpenLedger(filepath.Join(dir, "intent-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out := filepath.Join(dir, "out")
	result, err := InspectAuthorized(ctx, AuthorizedRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Profile: "quick", Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  bindings, Intent: authorizedLabIntent(t, inv), Profile: "quick", OutDir: out,
		IntentLedger: ledger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		t.Fatalf("product flags set: %+v", result)
	}
	if result.JobStatus == domain.JobCompleted || result.JobStatusReason == "" || result.ReportPath == "" {
		t.Fatalf("incomplete aggregate result: %+v", result)
	}
	if !strings.Contains(result.JobStatusReason, "PARTIAL") && !strings.Contains(result.JobStatusReason, "not a production completed scan") {
		t.Fatalf("missing honest PARTIAL reason: %s", result.JobStatusReason)
	}
	raw, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"collector_available": false`) || strings.Contains(string(raw), `"evidence"`) {
		t.Fatalf("aggregate report is missing flags or leaked raw evidence: %s", raw)
	}
	if len(result.HostSummaries) != 2 {
		t.Fatalf("summaries=%d", len(result.HostSummaries))
	}
	_, err = InspectAuthorized(ctx, AuthorizedRequest{
		Inventory: inv,
		Allowlist: authorization.CollectionAllowlist{Version: 1, Profile: "quick", Hosts: []string{"linux-box-lab-ssh-001", "linux-box-lab-ssh-002"}},
		Bindings:  bindings, Intent: authorizedLabIntent(t, inv), Profile: "quick", OutDir: filepath.Join(dir, "replay"),
		IntentLedger: ledger,
	})
	if err == nil {
		t.Fatal("replayed live intent accepted")
	}
}

func TestInspectAuthorizedLivePressureKeepsFirstHost(t *testing.T) {
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
		Pressure: &SequencePressure{After: 1, Reason: "stop after first authorized host"},
	})
	if err == nil {
		t.Fatal("pressure after first host returned success")
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady || result.JobStatus == domain.JobCompleted {
		t.Fatalf("unsafe result: %+v", result)
	}
	if result.ReportPath == "" || len(result.Hosts) != 2 {
		t.Fatalf("incomplete partial result: %+v", result)
	}
	if result.Hosts[0].HostID != "linux-box-lab-ssh-001" || result.Hosts[0].ReportPath == "" {
		t.Fatalf("first host was not kept: %+v", result.Hosts[0])
	}
	if result.Hosts[1].HostID != "linux-box-lab-ssh-002" || result.Hosts[1].ReportPath != "" {
		t.Fatalf("second host should have been skipped: %+v", result.Hosts[1])
	}
}
