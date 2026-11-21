package linux

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestLiveRootStillRejectedWithoutLiveFlag(t *testing.T) {
	result, err := (System{Root: "/", Now: time.Now}).Collect(context.Background(), identityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotAvailable || result.ErrorCode != "ROOT_REJECTED" {
		t.Fatalf("live root accepted without flag: %+v", result)
	}
}

func TestLiveLinuxCollectorsReadThisHost(t *testing.T) {
	if os.Getenv("HOSTSEC_LIVE_LINUX") != "1" {
		t.Skip("set HOSTSEC_LIVE_LINUX=1 to run live root filesystem collectors")
	}
	if runtime.GOOS != "linux" {
		t.Skip("live collectors require linux")
	}
	now := time.Now
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	base := collector.Request{
		ScanID: "scan-lab-001", AttemptID: "attempt-lab-001", HostID: "linux-box-lab-001",
		Profile: "standard", PolicyVersion: "1.0",
		Limits: collector.Limits{Timeout: 30 * time.Second, MaxRecords: 512, MaxBytes: 1 << 20},
	}

	idReq := base
	idReq.ModuleID = ModuleHostIdentity
	ident := CollectModule(ctx, "/", true, now, idReq)
	if ident.Status != domain.CollectionSuccess && ident.Status != domain.CollectionPartial {
		t.Fatalf("identity: %+v", ident)
	}
	if len(ident.Records) == 0 {
		t.Fatal("identity produced no records")
	}
	rec := ident.Records[0]
	osName, _ := rec["os"].(string)
	distribution, _ := rec["distribution"].(string)
	kernel, _ := rec["kernel"].(string)
	arch, _ := rec["architecture"].(string)
	if strings.TrimSpace(osName) == "" || osName == "unknown" {
		t.Fatalf("os missing or unknown: %+v", rec)
	}
	if strings.TrimSpace(distribution) == "" || distribution == "unknown" {
		t.Fatalf("distribution missing or unknown: %+v", rec)
	}
	if strings.TrimSpace(kernel) == "" {
		t.Fatalf("kernel missing: %+v", rec)
	}
	if strings.TrimSpace(arch) == "" {
		t.Fatalf("architecture missing: %+v", rec)
	}
	// Identity.os is the os-release ID (debian, ubuntu, ...). Do not require
	// the substring "linux" in NAME/distribution; Ubuntu's NAME is "Ubuntu".
	if ident.Records[0]["architecture"] != runtime.GOARCH && ident.Records[0]["architecture"] != "x86_64" && ident.Records[0]["architecture"] != "amd64" {
		t.Logf("architecture=%v goarch=%s", ident.Records[0]["architecture"], runtime.GOARCH)
	}

	for _, module := range []string{ModuleProcessInventory, ModuleNetworkInventory, ModuleAccountInventory, ModuleServiceInventory, ModulePersistenceInventory, ModuleSecurityConfig, ModulePackageInventory, ModuleTargetedFileScan} {
		req := base
		req.ModuleID = module
		got := CollectModule(ctx, "/", true, now, req)
		if got.Status == domain.CollectionNotAvailable && got.ErrorCode == "ROOT_REJECTED" {
			t.Fatalf("%s rejected live root", module)
		}
		if got.Status == domain.CollectionFailed && len(got.Records) == 0 && module != ModuleTargetedFileScan {
			t.Fatalf("%s failed: %+v", module, got)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(strings.ToLower(string(raw)), "-----begin") || strings.Contains(string(raw), "PRIVATE KEY") {
			t.Fatalf("%s leaked private key material", module)
		}
		t.Logf("%s status=%s records=%d warnings=%d", module, got.Status, len(got.Records), len(got.Warnings))
	}
}
