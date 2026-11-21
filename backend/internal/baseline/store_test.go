package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFirstScanIsCandidateNotChange(t *testing.T) {
	snap := Candidate("linux-test-001", "scan-fixture-001")
	if snap.Trusted() {
		t.Fatal("first scan cannot be a trusted baseline")
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(path, snap); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusCandidate {
		t.Fatalf("status=%s", got.Status)
	}
	diff := Compare(got, got)
	if diff.Status != DiffUnknown {
		t.Fatalf("unapproved compare status=%s", diff.Status)
	}
}

func TestApproveVerifyHistoryAndTamper(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	first := Candidate("linux-test-001", "scan-fixture-001")
	first.Identity = HostIdentity{HostID: "linux-test-001", OS: "debian", Distribution: "Debian GNU/Linux"}
	first.SSHKeys = []string{"ssh-ed25519 AAAA"}
	first.SSHConfigHash = "aaa"
	first.Services = []string{"ssh.service"}
	first.UID0 = []string{"root"}
	if err := store.RecordCandidate(first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approved("linux-test-001"); err != ErrNoApproved {
		t.Fatalf("unapproved first scan treated as baseline: %v", err)
	}
	now := time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC)
	trusted, err := store.Approve("linux-test-001", "scan-fixture-001", "approver-bob", now)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted.Trusted() {
		t.Fatal("approved snapshot not trusted")
	}
	if err := store.VerifyFile(filepath.Join(store.hostDir("linux-test-001"), "trusted.json")); err != nil {
		t.Fatal(err)
	}
	same := first
	same.Status = StatusCandidate
	if diff := Compare(same, trusted); diff.Status != DiffUnchanged {
		t.Fatalf("expected unchanged, got %+v", diff)
	}
	changed := same
	changed.SSHKeys = []string{"ssh-ed25519 BBBB"}
	changed.Identity.Distribution = "Ubuntu"
	changed.Services = []string{"ssh.service", "cron.service"}
	changed.SSHConfigHash = "bbb"
	diff := Compare(changed, trusted)
	if diff.Status != DiffChanged || len(diff.SSHKeys) == 0 || len(diff.Identity) == 0 || len(diff.Services) == 0 || len(diff.SSHConfig) == 0 {
		t.Fatalf("incomplete diff: %+v", diff)
	}

	// Tamper the trusted file without updating the append-only index.
	tampered := trusted
	tampered.UID0 = []string{"root", "backdoor"}
	if err := Save(filepath.Join(store.hostDir("linux-test-001"), "trusted.json"), tampered); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyFile(filepath.Join(store.hostDir("linux-test-001"), "trusted.json")); err != ErrTamper {
		t.Fatalf("tamper accepted: %v", err)
	}
	// Even recomputing the hash in the file must fail against the index.
	hash, err := HashPayload(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tampered.PayloadHash = hash
	if err := Save(filepath.Join(store.hostDir("linux-test-001"), "trusted.json"), tampered); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyFile(filepath.Join(store.hostDir("linux-test-001"), "trusted.json")); err != ErrTamper {
		t.Fatalf("hash-rewritten tamper accepted: %v", err)
	}

	history, err := store.History("linux-test-001")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) < 2 || history[0].Action != "record_candidate" || history[1].Action != "approve" {
		t.Fatalf("history=%+v", history)
	}
}

func TestTruncatedIndexRejected(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	path := filepath.Join(store.Dir, "index.jsonl")
	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"host_id":"linux-test-001"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.lastIndex("linux-test-001"); err == nil {
		t.Fatal("truncated index accepted")
	}
}
