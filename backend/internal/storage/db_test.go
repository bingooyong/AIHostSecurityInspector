package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestMigrateIsIdempotentAndChecksummed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "hostsec.sqlite")
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("db mode=%o", info.Mode().Perm())
	}
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := domain.Evidence{
		EvidenceID: "evidence-db-001", HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		CollectedAt: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC).Format(domain.TimeLayout),
		ReceivedAt:  time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC).Format(domain.TimeLayout),
		Module:      "account_inventory", CollectorVersion: "0.1.0", Category: "account",
		RawSummary: "db fixture", NormalizedData: map[string]any{"ok": true},
		SHA256: &hash, NormalizedSHA256: &hash, CollectionStatus: domain.CollectionSuccess,
		IntegrityStatus: domain.IntegrityUnverified, Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
	if err := db.InsertEvidence(ctx, ev, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertEvidence(ctx, ev, nil); err == nil {
		t.Fatal("duplicate metadata accepted")
	}
	_ = db.Close()
	again, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	got, err := again.GetEvidence(ctx, ev.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Module != ev.Module {
		t.Fatalf("got %+v", got)
	}
}

func TestMemoryPathRejected(t *testing.T) {
	_, err := Open(context.Background(), ":memory:")
	if err == nil {
		t.Fatal("memory sqlite accepted")
	}
}

func TestDiskFullClassification(t *testing.T) {
	if !errors.Is(ClassifyIO(syscall.ENOSPC), ErrDiskFull) {
		t.Fatal("expected disk full")
	}
}
