package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func processReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModuleProcessInventory, Profile: domain.ProfileQuick, PolicyVersion: "0.1.0",
	}
}

func TestProcessInventoryClassifiesExeReasons(t *testing.T) {
	col := Process{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := col.Collect(context.Background(), processReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	byPID := map[int]map[string]any{}
	for _, rec := range result.Records {
		pid := int(rec["pid"].(float64))
		byPID[pid] = rec
	}
	systemd := byPID[1]
	if systemd == nil || systemd["exe_reason"] != "exe_exists" || systemd["ppid"].(float64) != 0 || systemd["uid"].(float64) != 0 {
		t.Fatalf("pid 1 %+v", systemd)
	}
	want := sha256.Sum256([]byte("fake-systemd-elf\n"))
	if systemd["exe_sha256"] != hex.EncodeToString(want[:]) {
		t.Fatalf("pid 1 hash %v", systemd["exe_sha256"])
	}
	kthread := byPID[2]
	if kthread == nil || kthread["exe_reason"] != "kernel_thread" || kthread["exe_exists"].(bool) {
		t.Fatalf("kernel thread misclassified %+v", kthread)
	}
	missing := byPID[99]
	if missing == nil || missing["exe_reason"] != "exe_missing" {
		t.Fatalf("missing binary misclassified %+v", missing)
	}
	demo := byPID[10]
	if demo == nil || demo["uid"].(float64) != 1000 || demo["start_ticks"].(float64) != 999 {
		t.Fatalf("pid 10 %+v", demo)
	}
}

func TestPermissionDeniedIsNotMissing(t *testing.T) {
	col := Process{Root: fixtureRoot(t, "host"), view: permView{deny: "proc/7/exe"}, Now: time.Now}
	req := processReq()
	// permView lists only pid 7
	result, err := col.Collect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%v warnings=%v", result.Records, result.Warnings)
	}
	rec := result.Records[0]
	if rec["exe_reason"] != "permission_denied" || rec["exe_exists"].(bool) {
		t.Fatalf("EACCES treated as missing %+v", rec)
	}
}

type permView struct{ deny string }

func (p permView) ReadFile(name string) ([]byte, error) {
	switch name {
	case "proc/7/stat":
		return []byte("7 (secret) S 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 8 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"), nil
	case "proc/7/status":
		return []byte("Uid:\t0\t0\t0\t0\n"), nil
	case "proc/7/cmdline":
		return []byte("secret\x00"), nil
	default:
		return nil, fs.ErrNotExist
	}
}
func (p permView) Lstat(name string) (fs.FileInfo, error) {
	if name == p.deny {
		return nil, fs.ErrPermission
	}
	return nil, fs.ErrNotExist
}
func (p permView) Readlink(name string) (string, error) {
	if name == p.deny {
		return "", os.ErrPermission
	}
	return "", fs.ErrNotExist
}
func (permView) ReadDir(string) ([]fs.DirEntry, error) {
	return []fs.DirEntry{fakeDir("7")}, nil
}
func (permView) Close() error { return nil }

type fakeDir string

func (f fakeDir) Name() string             { return string(f) }
func (fakeDir) IsDir() bool                { return true }
func (fakeDir) Type() fs.FileMode          { return fs.ModeDir }
func (fakeDir) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

func TestDeletedBinaryReason(t *testing.T) {
	view := deletedView{}
	col := Process{Root: fixtureRoot(t, "host"), view: view, Now: time.Now}
	result, err := col.Collect(context.Background(), processReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Records[0]["exe_reason"] != "deleted" || result.Records[0]["exe_exists"].(bool) {
		t.Fatalf("deleted binary %+v", result.Records[0])
	}
}

type deletedView struct{}

func (deletedView) ReadFile(name string) ([]byte, error) {
	switch name {
	case "proc/11/stat":
		return []byte("11 (gone) S 1 11 11 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"), nil
	case "proc/11/status":
		return []byte("Uid:\t1\t1\t1\t1\n"), nil
	case "proc/11/cmdline":
		return []byte("gone\x00"), nil
	default:
		return nil, fs.ErrNotExist
	}
}
func (deletedView) Lstat(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }
func (deletedView) Readlink(string) (string, error)   { return "/usr/bin/gone (deleted)", nil }
func (deletedView) ReadDir(string) ([]fs.DirEntry, error) {
	return []fs.DirEntry{fakeDir("11")}, nil
}
func (deletedView) Close() error { return nil }

func TestProcessTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	col := Process{Root: fixtureRoot(t, "host"), view: hangView{ctx: ctx}, Now: time.Now}
	result, err := col.Collect(ctx, processReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionTimeout {
		t.Fatalf("status=%s", result.Status)
	}
}
