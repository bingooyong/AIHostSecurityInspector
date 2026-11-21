package baseline

import (
	"path/filepath"
	"testing"
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
}
