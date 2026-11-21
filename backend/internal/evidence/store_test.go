package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/storage"
)

func TestPutGetAndPermissions(t *testing.T) {
	store := openStore(t)
	raw := []byte("fixture-raw-bytes")
	in := sampleInput("evidence-fixture-001", raw)
	got, err := store.Put(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntegrityStatus != domain.IntegrityUnverified {
		t.Fatalf("integrity=%s", got.IntegrityStatus)
	}
	if got.SupportsDetection() {
		t.Fatal("unverified evidence must not support detection")
	}
	meta, err := store.GetMetadata(context.Background(), in.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if meta.HostID != in.HostID || meta.ScanID != in.ScanID {
		t.Fatalf("meta %+v", meta)
	}
	reader, err := store.OpenRaw(context.Background(), in.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(raw) {
		t.Fatalf("raw=%q", body)
	}
	sum := sha256.Sum256(raw)
	if meta.SHA256 == nil || *meta.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha=%v", meta.SHA256)
	}
	assertMode(t, filepath.Join(store.root, "hostsec.sqlite"), 0o600)
	assertMode(t, filepath.Join(store.root, "objects"), 0o700)
	assertMode(t, filepath.Join(store.root, "objects", "raw."+in.EvidenceID), 0o600)
}

func TestAppendOnlyRejectsDuplicate(t *testing.T) {
	store := openStore(t)
	in := sampleInput("evidence-fixture-002", []byte("one"))
	if _, err := store.Put(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	in.Raw = []byte("two")
	_, err := store.Put(context.Background(), in)
	if err == nil {
		t.Fatal("duplicate accepted")
	}
	var domainErr *domain.Error
	if !errors.As(err, &domainErr) || domainErr.Code != domain.CodeDuplicateID {
		if !errors.Is(err, storage.ErrAppendOnly) {
			t.Fatalf("err=%v", err)
		}
	}
	reader, err := store.OpenRaw(context.Background(), in.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	body, _ := io.ReadAll(reader)
	if string(body) != "one" {
		t.Fatalf("overwrote raw: %q", body)
	}
}

func TestRecoverQuarantinesOrphansAndTmp(t *testing.T) {
	store := openStore(t)
	if err := os.WriteFile(filepath.Join(store.root, "objects", "obj.orphan-1"), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.root, "tmp", "obj.partial-1.partial"), []byte("tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := store.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Quarantined) != 2 {
		t.Fatalf("quarantined=%v", report.Quarantined)
	}
	if _, err := os.Lstat(filepath.Join(store.root, "objects", "obj.orphan-1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan object remained in objects/")
	}
	if _, err := os.Lstat(filepath.Join(store.root, "orphans", "obj.orphan-1")); err != nil {
		t.Fatal("orphan was deleted instead of quarantined")
	}
}

func TestPutCanceledDoesNotCommit(t *testing.T) {
	store := openStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.Put(ctx, sampleInput("evidence-fixture-003", []byte("raw")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if _, err := store.GetMetadata(context.Background(), "evidence-fixture-003"); err == nil {
		t.Fatal("canceled put persisted metadata")
	}
}

func TestPathTraversalObjectIDRejected(t *testing.T) {
	store := openStore(t)
	_, err := store.objectPath("../etc/passwd")
	if err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestClassifyDiskFull(t *testing.T) {
	if !errors.Is(storage.ClassifyIO(syscall.ENOSPC), storage.ErrDiskFull) {
		t.Fatal("ENOSPC not classified")
	}
}

func TestConcurrentDistinctPuts(t *testing.T) {
	store := openStore(t)
	errCh := make(chan error, 2)
	for i, id := range []string{"evidence-fixture-a", "evidence-fixture-b"} {
		go func(id string, n int) {
			in := sampleInput(id, []byte{byte(n)})
			_, err := store.Put(context.Background(), in)
			errCh <- err
		}(id, i)
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func openStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	store, err := Open(context.Background(), root, func() time.Time { return time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleInput(id string, raw []byte) Input {
	return Input{
		EvidenceID: id, HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		CollectedAt: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC),
		Module:      "account_inventory", CollectorVersion: "0.1.0", Category: "account",
		RawSummary: "synthetic fixture account inventory", CollectionStatus: domain.CollectionSuccess,
		Completeness: domain.CompletenessComplete, Warnings: []string{}, Raw: raw,
		Normalized: map[string]any{"users": []any{}},
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode=%o want=%o", path, info.Mode().Perm(), want)
	}
}
