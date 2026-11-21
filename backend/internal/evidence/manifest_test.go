package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestManifestVerifyAndTamper(t *testing.T) {
	store := openStore(t)
	if _, err := store.Put(context.Background(), sampleInput("evidence-manifest-001", []byte("raw-bytes"))); err != nil {
		t.Fatal(err)
	}
	man, err := store.BuildManifest(context.Background(), "scan-fixture-001", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if man.Signature != nil || len(man.Entries) != 2 {
		t.Fatalf("manifest %+v", man)
	}
	report, err := store.Verify(context.Background(), "scan-fixture-001")
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK || report.Integrity != domain.IntegrityVerified || report.SourceAuthenticity != "unverified" {
		t.Fatalf("report %+v", report)
	}
	meta, err := store.GetMetadata(context.Background(), "evidence-manifest-001")
	if err != nil {
		t.Fatal(err)
	}
	if !meta.SupportsDetection() {
		t.Fatal("verified dual-digest evidence should support detection")
	}
	if err := os.WriteFile(filepath.Join(store.root, "objects", "raw.evidence-manifest-001"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = store.Verify(context.Background(), "scan-fixture-001")
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || len(report.Mismatches) == 0 {
		t.Fatalf("tamper not detected %+v", report)
	}
	meta, err = store.GetMetadata(context.Background(), "evidence-manifest-001")
	if err != nil {
		t.Fatal(err)
	}
	if meta.IntegrityStatus != domain.IntegrityFailed || meta.SupportsDetection() {
		t.Fatalf("integrity=%s", meta.IntegrityStatus)
	}
}

func TestMissingRawDoesNotForgeHash(t *testing.T) {
	store := openStore(t)
	in := sampleInput("evidence-manifest-002", nil)
	in.CollectionStatus = domain.CollectionPartial
	in.Completeness = domain.CompletenessPartial
	in.Warnings = []string{"raw_unavailable"}
	got, err := store.Put(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != nil || got.RawRef != nil {
		t.Fatal("forged raw digest")
	}
	if got.SupportsDetection() {
		t.Fatal("partial evidence cannot support detection")
	}
}

func TestMissingObjectFailsVerify(t *testing.T) {
	store := openStore(t)
	if _, err := store.Put(context.Background(), sampleInput("evidence-manifest-003", []byte("keep"))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BuildManifest(context.Background(), "scan-fixture-001", "0.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.root, "objects", "raw.evidence-manifest-003")); err != nil {
		t.Fatal(err)
	}
	report, err := store.Verify(context.Background(), "scan-fixture-001")
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || len(report.Missing) == 0 {
		t.Fatalf("missing object not reported %+v", report)
	}
}

func TestCorruptManifestAndCrossScanAreRejected(t *testing.T) {
	store := openStore(t)
	if _, err := store.Put(context.Background(), sampleInput("evidence-manifest-004", []byte("keep"))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BuildManifest(context.Background(), "scan-fixture-001", "0.1.0"); err != nil {
		t.Fatal(err)
	}
	report, err := store.Verify(context.Background(), "scan-other-001")
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatal("cross-scan manifest verified")
	}
	if err := os.WriteFile(filepath.Join(store.root, "manifest.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadManifest(); err == nil {
		t.Fatal("corrupt manifest loaded")
	}
	corrupt, err := store.Verify(context.Background(), "scan-fixture-001")
	if err == nil && corrupt.OK {
		t.Fatalf("corrupt manifest verified %+v", corrupt)
	}
}

func TestReplayObjectDoesNotForgeSecondScan(t *testing.T) {
	first := openStore(t)
	if _, err := first.Put(context.Background(), sampleInput("evidence-manifest-005", []byte("original"))); err != nil {
		t.Fatal(err)
	}
	man, err := first.BuildManifest(context.Background(), "scan-fixture-001", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	second := openStore(t)
	if _, err := second.Put(context.Background(), sampleInput("evidence-manifest-006", []byte("other-scan-bytes"))); err != nil {
		t.Fatal(err)
	}
	if _, err := second.BuildManifest(context.Background(), "scan-fixture-002", "0.1.0"); err != nil {
		t.Fatal(err)
	}
	// Replaying another scan's manifest into this store must not verify.
	payload, err := os.ReadFile(filepath.Join(first.root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second.root, "manifest.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := second.Verify(context.Background(), "scan-fixture-002")
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatalf("replayed manifest verified %+v %+v", report, man)
	}
}
