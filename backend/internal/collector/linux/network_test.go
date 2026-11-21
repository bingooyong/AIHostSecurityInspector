package linux

import (
	"context"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func networkReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModuleNetworkInventory, Profile: domain.ProfileQuick, PolicyVersion: "0.1.0",
	}
}

func TestNetworkInventoryMapsInodeAndDoesNotProbe(t *testing.T) {
	col := Network{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := col.Collect(context.Background(), networkReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	rec := result.Records[0]
	sockets, _ := rec["sockets"].([]any)
	if len(sockets) < 2 {
		t.Fatalf("sockets=%v", rec["sockets"])
	}
	foundListen := false
	foundUnresolved := false
	for _, item := range sockets {
		sock := item.(map[string]any)
		if sock["local_address"] == "127.0.0.1:80" && sock["listening"] == true && sock["pid_resolved"] == true && sock["pid"].(float64) == 1 {
			foundListen = true
		}
		if sock["inode"].(float64) == 99999 && sock["pid_resolved"] == false {
			foundUnresolved = true
		}
	}
	if !foundListen {
		t.Fatalf("listen socket not associated %+v", sockets)
	}
	if !foundUnresolved {
		t.Fatalf("unresolved inode was invented %+v", sockets)
	}
	if rec["dns_nameservers"].([]any)[0] != "192.0.2.53" {
		t.Fatalf("dns %+v", rec["dns_nameservers"])
	}
	fw := rec["firewall"].(map[string]any)
	if fw["status"] != "present" {
		t.Fatalf("firewall %+v", fw)
	}
}

func TestNetworkTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	col := Network{Root: fixtureRoot(t, "host"), view: hangView{ctx: ctx}, Now: time.Now}
	result, err := col.Collect(ctx, networkReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionTimeout {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestDecodeKernelAddresses(t *testing.T) {
	ip, ok := decodeKernelIP("0100007F", false)
	if !ok || ip != "127.0.0.1" {
		t.Fatalf("ipv4 %s %v", ip, ok)
	}
	ip, ok = decodeKernelIP("00000000000000000000000001000000", true)
	if !ok || ip != "0000:0000:0000:0000:0000:0000:0000:0001" {
		t.Fatalf("ipv6 %s %v", ip, ok)
	}
}
