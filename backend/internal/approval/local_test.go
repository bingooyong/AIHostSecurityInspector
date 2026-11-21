package approval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func testdataPath(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func loadFixtureIntent(t *testing.T) domain.ExecutionIntent {
	t.Helper()
	payload, err := os.ReadFile(testdataPath(t, "intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var intent domain.ExecutionIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestLocalVerifierAcceptsFixtureAndRejectsNegatives(t *testing.T) {
	intent := loadFixtureIntent(t)
	now := time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC)
	verifier, err := OpenLocal(testdataPath(t, "trust-store.json"), filepath.Join(t.TempDir(), "ledger.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyFile(testdataPath(t, "approval-valid.json"), intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Consume(verified); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Consume(verified); err != ErrReplay {
		t.Fatalf("replay got %v", err)
	}

	if _, err := verifier.VerifyFile(testdataPath(t, "approval-tampered.json"), intent); err == nil {
		t.Fatal("tampered approval accepted")
	}
	if _, err := verifier.VerifyFile(testdataPath(t, "approval-revoked.json"), intent); err != ErrRevoked {
		t.Fatalf("revoked got %v", err)
	}

	// Cross-target / plan drift: host list change must not verify against the frozen approval.
	drifted := intent
	drifted.HostIDs = []string{"linux-other-001"}
	drifted.IdentityRefs = []string{"hostid-linux-other-001"}
	if _, err := verifier.VerifyFile(testdataPath(t, "approval-valid.json"), drifted); err != ErrIntentMismatch {
		t.Fatalf("cross-target got %v", err)
	}

	expired, err := verifier.VerifyFile(testdataPath(t, "approval-valid.json"), intent)
	if err != nil {
		t.Fatal(err)
	}
	_ = expired
	old := *verifier
	old.Now = func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }
	if _, err := old.VerifyFile(testdataPath(t, "approval-valid.json"), intent); err != ErrExpired {
		t.Fatalf("expired got %v", err)
	}
}

func TestVerifyLocalRejectsMissingDocument(t *testing.T) {
	intent := loadFixtureIntent(t)
	store, err := LoadTrustStore(testdataPath(t, "trust-store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLocal(store, Document{ApprovalID: "approval-missing"}, intent, time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC)); err == nil {
		t.Fatal("empty approval accepted")
	}
}
