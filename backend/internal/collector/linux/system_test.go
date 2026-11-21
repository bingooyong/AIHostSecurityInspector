package linux

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func fixtureRoot(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func identityReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModuleHostIdentity, Profile: domain.ProfileQuick, PolicyVersion: "0.1.0",
	}
}

func TestHostIdentityFromFixture(t *testing.T) {
	sys := System{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := sys.Collect(context.Background(), identityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess || result.Completeness != domain.CompletenessComplete {
		t.Fatalf("unexpected status %+v", result)
	}
	payload, _ := json.Marshal(result.Records)
	if strings.Contains(string(payload), "0123456789abcdef0123456789abcdef") || strings.Contains(string(payload), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") {
		t.Fatal("raw machine-id or boot-id leaked")
	}
	rec := result.Records[0]
	if rec["os"] != "debian" || rec["os_version"] != "12" || rec["kernel"] != "6.1.0-0-amd64" || rec["architecture"] != "x86_64" {
		t.Fatalf("identity fields %+v", rec)
	}
	if rec["boot_time"] != "2023-11-14T22:13:20Z" || rec["cpu_count"].(float64) != 2 || rec["memory_kb"].(float64) != 2048000 {
		t.Fatalf("resource/boot fields %+v", rec)
	}
	if rec["view"] != "host" {
		t.Fatalf("view=%v", rec["view"])
	}
	fp, _ := rec["identity_fingerprint"].(string)
	if !domain.ValidSHA256(fp) {
		t.Fatal("fingerprint is not sha256")
	}
}

func TestHostIdentityFromUbuntuFixture(t *testing.T) {
	sys := System{Root: fixtureRoot(t, "ubuntu"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := sys.Collect(context.Background(), identityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess || result.Completeness != domain.CompletenessComplete {
		t.Fatalf("unexpected status %+v", result)
	}
	payload, _ := json.Marshal(result.Records)
	if strings.Contains(string(payload), "ubuntu-fixture-machine-id-24") || strings.Contains(string(payload), "bbbbbbbb-cccc-dddd-eeee-ffffffffffff") {
		t.Fatal("raw machine-id or boot-id leaked")
	}
	rec := result.Records[0]
	if rec["os"] != "ubuntu" {
		t.Fatalf("os should be os-release ID, got %+v", rec)
	}
	if rec["distribution"] != "Ubuntu" {
		t.Fatalf("distribution should be os-release NAME, got %+v", rec)
	}
	if rec["os_version"] != "24.04" || rec["version_codename"] != "noble" {
		t.Fatalf("ubuntu version fields %+v", rec)
	}
	if rec["kernel"] != "6.8.0-1014-aws" || rec["architecture"] != "x86_64" {
		t.Fatalf("kernel/arch %+v", rec)
	}
	if rec["boot_time"] != "2023-11-14T22:13:20Z" || rec["cpu_count"].(float64) != 2 || rec["memory_kb"].(float64) != 2048000 {
		t.Fatalf("resource/boot fields %+v", rec)
	}
	if rec["view"] != "host" {
		t.Fatalf("view=%v", rec["view"])
	}
	dist, _ := rec["distribution"].(string)
	if strings.Contains(strings.ToLower(dist), "linux") {
		t.Fatal("ubuntu fixture NAME unexpectedly contains linux; this test must not depend on that substring")
	}
	fp, _ := rec["identity_fingerprint"].(string)
	if !domain.ValidSHA256(fp) {
		t.Fatal("fingerprint is not sha256")
	}
}

func TestContainerViewIsLabeled(t *testing.T) {
	sys := System{Root: fixtureRoot(t, "container"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := sys.Collect(context.Background(), identityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	if result.Records[0]["view"] != "container" {
		t.Fatalf("expected container view, got %+v", result.Records[0])
	}
}

func TestPartialIdentityWhenFilesMissing(t *testing.T) {
	sys := System{Root: fixtureRoot(t, "partial"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := sys.Collect(context.Background(), identityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
}

func TestLiveRootAndEscapeAreRejectedOrContained(t *testing.T) {
	sys := System{Root: "/", Now: time.Now}
	result, err := sys.Collect(context.Background(), identityReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotAvailable || result.ErrorCode != "ROOT_REJECTED" {
		t.Fatalf("live root accepted %+v", result)
	}
	escaped := System{Root: fixtureRoot(t, "escape"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err = escaped.Collect(context.Background(), identityReq())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(result)
	if strings.Contains(string(payload), "root:") || strings.Contains(strings.ToLower(string(payload)), "password") {
		t.Fatal("symlink escape leaked host file")
	}
}

func TestTimeoutStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	sys := System{Root: fixtureRoot(t, "host"), view: hangView{ctx: ctx}, Now: time.Now}
	req := identityReq()
	req.Limits.Timeout = 20 * time.Millisecond
	result, err := sys.Collect(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionTimeout {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestFingerprintChangesWithMachineID(t *testing.T) {
	sys := System{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	first, _ := sys.Collect(context.Background(), identityReq())
	dir := t.TempDir()
	if err := copyDir(fixtureRoot(t, "host"), dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "machine-id"), []byte("ffffffffffffffffffffffffffffffff\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, _ := System{Root: dir, Now: sys.Now}.Collect(context.Background(), identityReq())
	if first.Records[0]["identity_fingerprint"] == second.Records[0]["identity_fingerprint"] {
		t.Fatal("fingerprint ignored machine-id")
	}
}

func TestIPHostIDRejected(t *testing.T) {
	req := identityReq()
	req.HostID = "127.0.0.1"
	_, err := (System{Root: fixtureRoot(t, "host")}).Collect(context.Background(), req)
	if err == nil {
		t.Fatal("IP host_id accepted")
	}
}

type hangView struct{ ctx context.Context }

func (h hangView) ReadFile(string) ([]byte, error) {
	<-h.ctx.Done()
	return nil, h.ctx.Err()
}
func (h hangView) Lstat(string) (fs.FileInfo, error) {
	<-h.ctx.Done()
	return nil, h.ctx.Err()
}
func (h hangView) Readlink(string) (string, error) {
	<-h.ctx.Done()
	return "", h.ctx.Err()
}
func (h hangView) ReadDir(string) ([]fs.DirEntry, error) {
	<-h.ctx.Done()
	return nil, h.ctx.Err()
}
func (hangView) Close() error { return nil }

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.Type()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
