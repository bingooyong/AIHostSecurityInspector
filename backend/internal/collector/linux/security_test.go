package linux

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func securityReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModuleSecurityConfig, Profile: domain.ProfileQuick, PolicyVersion: "0.1.0",
	}
}

func TestSecurityConfigDoesNotTreatMissingAsCompliant(t *testing.T) {
	col := Security{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := col.Collect(context.Background(), securityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	rec := result.Records[0]
	ssh := rec["ssh"].(map[string]any)
	if ssh["permit_root_login"] != "prohibit-password" || ssh["complete_policy"] != true || ssh["include_unresolved"] != false {
		t.Fatalf("sshd Include was not applied last-wins %+v", ssh)
	}
	includes, _ := json.Marshal(ssh["includes"])
	if !strings.Contains(string(includes), "sshd_config.d") {
		t.Fatalf("resolved includes missing: %s", includes)
	}
	sudo, _ := json.Marshal(rec["sudo"])
	if !strings.Contains(string(sudo), "etc/sudoers.d/fixture-svc") {
		t.Fatalf("sudoers.d path was not collected: %s", sudo)
	}
	caveats := rec["caveats"].([]any)
	joined := strings.Join(stringify(caveats), ",")
	if !strings.Contains(joined, "missing_config_is_not_compliant") {
		t.Fatalf("caveats=%v", caveats)
	}
	payload, _ := json.Marshal(result)
	if strings.Contains(string(payload), "compliant=true") {
		t.Fatal("missing config marked compliant")
	}
}

func TestSecurityLiveRootRejected(t *testing.T) {
	result, err := (Security{Root: "/", Now: time.Now}).Collect(context.Background(), securityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotAvailable {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSecurityIncludeEscapeDoesNotReadOutsideRoot(t *testing.T) {
	col := Security{Root: fixtureRoot(t, "ssh-escape"), Now: time.Now}
	result, err := col.Collect(context.Background(), securityReq())
	if err != nil {
		t.Fatal(err)
	}
	ssh := result.Records[0]["ssh"].(map[string]any)
	if ssh["permit_root_login"] != "no" || ssh["include_unresolved"] != true || ssh["complete_policy"] != false {
		t.Fatalf("escaped include applied host file: %+v", ssh)
	}
}

func TestSecurityIncludeDepthIsBounded(t *testing.T) {
	col := Security{Root: fixtureRoot(t, "ssh-deep"), Now: time.Now}
	result, err := col.Collect(context.Background(), securityReq())
	if err != nil {
		t.Fatal(err)
	}
	ssh := result.Records[0]["ssh"].(map[string]any)
	if ssh["permit_root_login"] == "yes" || ssh["include_unresolved"] != true {
		t.Fatalf("unbounded include chain: %+v warnings=%v", ssh, result.Warnings)
	}
}

func TestSecurityTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	col := Security{Root: fixtureRoot(t, "host"), view: hangView{ctx: ctx}, Now: time.Now}
	req := securityReq()
	req.Limits.Timeout = 20 * time.Millisecond
	result, err := col.Collect(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionTimeout {
		t.Fatalf("status=%s", result.Status)
	}
}
