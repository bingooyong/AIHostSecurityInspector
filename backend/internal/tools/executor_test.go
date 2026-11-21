package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestExecutorDoesNotClaimCleanWhenMissing(t *testing.T) {
	res, err := (Executor{}).Run(context.Background(), Request{Tool: ToolClamAV, HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.CollectionNotAvailable || res.Findings != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestUnknownToolRejected(t *testing.T) {
	res, err := (Executor{}).Run(context.Background(), Request{Tool: "bash", HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.CollectionFailed || res.Warning != "unknown_tool" {
		t.Fatalf("%+v", res)
	}
}

func fixtureLookPath(t *testing.T) func(string) (string, error) {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", "bin"))
	if err != nil {
		t.Fatal(err)
	}
	return func(name string) (string, error) {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			return "", err
		}
		return path, nil
	}
}

func TestRunnerFixturesTimeoutLimitAndMissing(t *testing.T) {
	look := fixtureLookPath(t)
	ok := Runner{LookPath: look, Specs: map[string]Spec{
		"ok": {Name: "ok", Binary: "ok-tool", Args: []string{}, VersionArgs: []string{"--version"}, Timeout: 3 * time.Second, MaxOutput: 4096},
	}}
	res, err := ok.Run(context.Background(), Request{Tool: "ok", HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("ok tool: %+v %v", res, err)
	}

	slow := Runner{LookPath: look, Specs: map[string]Spec{
		"slow": {Name: "slow", Binary: "slow-tool", Args: []string{}, VersionArgs: []string{"--version"}, Timeout: 200 * time.Millisecond, MaxOutput: 4096},
	}}
	res, err = slow.Run(context.Background(), Request{Tool: "slow", HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil || res.Status != domain.CollectionTimeout {
		t.Fatalf("slow tool: %+v %v", res, err)
	}

	big := Runner{LookPath: look, Specs: map[string]Spec{
		"big": {Name: "big", Binary: "big-tool", Args: []string{}, VersionArgs: []string{"--version"}, Timeout: 3 * time.Second, MaxOutput: 256},
	}}
	res, err = big.Run(context.Background(), Request{Tool: "big", HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil || res.Status != domain.CollectionFailed || res.Warning != "output_limit" {
		t.Fatalf("big tool: %+v %v", res, err)
	}

	fail := Runner{LookPath: look, Specs: map[string]Spec{
		"fail": {Name: "fail", Binary: "fail-tool", Args: []string{}, VersionArgs: []string{"--version"}, Timeout: 3 * time.Second, MaxOutput: 4096},
	}}
	res, err = fail.Run(context.Background(), Request{Tool: "fail", HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil || res.Status != domain.CollectionFailed || res.Findings != 0 {
		t.Fatalf("fail tool: %+v %v", res, err)
	}

	missing := Runner{LookPath: look, Specs: map[string]Spec{
		ToolClamAV: {Name: ToolClamAV, Binary: "clamdscan", Args: []string{"--version"}, VersionArgs: []string{"--version"}, Timeout: time.Second, MaxOutput: 4096},
	}}
	res, err = missing.Run(context.Background(), Request{Tool: ToolClamAV, HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil || res.Status != domain.CollectionNotAvailable {
		t.Fatalf("missing: %+v %v", res, err)
	}
}

func TestAdapterWiresRunnerAndStaysHonestWhenMissing(t *testing.T) {
	look := fixtureLookPath(t)
	adapter := Adapter{Runner: Runner{LookPath: look, Specs: map[string]Spec{
		ToolLynis: {Name: ToolLynis, Binary: "ok-tool", Args: []string{}, VersionArgs: []string{"--version"}, Timeout: 3 * time.Second, MaxOutput: 4096},
	}}}
	res, err := adapter.Lynis(context.Background(), Request{HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil || res.Status != domain.CollectionSuccess || res.Tool != ToolLynis {
		t.Fatalf("adapter fixture: %+v %v", res, err)
	}
	missing := Adapter{}
	res, err = missing.ClamAV(context.Background(), Request{HostID: "linux-test-001", ScanID: "scan-fixture-001"})
	if err != nil || res.Status != domain.CollectionNotAvailable {
		t.Fatalf("adapter missing: %+v %v", res, err)
	}
}
