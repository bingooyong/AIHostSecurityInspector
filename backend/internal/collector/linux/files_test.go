package linux

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func fileReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModuleTargetedFileScan, Profile: domain.ProfileStandard, PolicyVersion: "0.1.0",
	}
}

func TestTargetedFileScanWhitelistAndHidden(t *testing.T) {
	dir := t.TempDir()
	if err := copyDir(fixtureRoot(t, "host"), dir); err != nil {
		t.Fatal(err)
	}
	hidden := filepath.Join(dir, "usr", "local", "bin", ".hidden-tool")
	if err := os.Chmod(hidden, 0o4755); err != nil {
		t.Fatal(err)
	}
	col := Files{Root: dir, Now: time.Now}
	result, err := col.Collect(context.Background(), fileReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	foundHidden := false
	for _, rec := range result.Records {
		if rec["path"] == "usr/local/bin/.hidden-tool" {
			foundHidden = rec["hidden"] == true
		}
		if rec["path"] == "etc/passwd" {
			t.Fatal("walked outside allowlist")
		}
	}
	if !foundHidden {
		t.Fatalf("hidden file not recorded records=%v", result.Records)
	}
}

func TestSUIDBitFromLstat(t *testing.T) {
	rec, _, _ := inspectFile(suidView{}, "usr/local/bin/demo", "demo")
	if !rec.SUID || rec.SGID {
		t.Fatalf("%+v", rec)
	}
}

type suidInfo struct{}

func (suidInfo) Name() string       { return "demo" }
func (suidInfo) Size() int64        { return 1 }
func (suidInfo) Mode() fs.FileMode  { return 0o755 | fs.ModeSetuid }
func (suidInfo) ModTime() time.Time { return time.Time{} }
func (suidInfo) IsDir() bool        { return false }
func (suidInfo) Sys() any           { return nil }

type suidView struct{}

func (suidView) ReadFile(string) ([]byte, error)       { return []byte("x"), nil }
func (suidView) Lstat(string) (fs.FileInfo, error)     { return suidInfo{}, nil }
func (suidView) Readlink(string) (string, error)       { return "", fs.ErrInvalid }
func (suidView) ReadDir(string) ([]fs.DirEntry, error) { return nil, nil }
func (suidView) Close() error                          { return nil }

func TestFileSymlinkIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "usr", "local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(bin, "escape")); err != nil {
		t.Fatal(err)
	}
	col := Files{Root: dir, Now: time.Now}
	result, err := col.Collect(context.Background(), fileReq())
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range result.Records {
		if rec["symlink"] == true && rec["rejected"] != "symlink_not_followed" {
			t.Fatalf("symlink followed %+v", rec)
		}
		if rec["sha256"] != nil && rec["sha256"] != "" && rec["symlink"] == true {
			t.Fatal("hashed symlink target")
		}
	}
}

func TestFileLiveRootRejected(t *testing.T) {
	result, err := (Files{Root: "/", Now: time.Now}).Collect(context.Background(), fileReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotAvailable {
		t.Fatalf("status=%s", result.Status)
	}
}
