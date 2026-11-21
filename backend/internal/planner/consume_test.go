package planner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/audit"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestPreflightConsumeUsesLedgerAndJournal(t *testing.T) {
	inv := inventory(t)
	intent, err := BuildIntent(t.Context(), inv, IntentRequest{
		HostID: "linux-test-001", Profile: "deep", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-20T00:00:00Z", ValidUntil: "2026-11-20T06:00:00Z",
		Window: &domain.MaintenanceWindow{Timezone: "UTC", Start: "2026-11-20T01:00:00Z", End: "2026-11-20T03:00:00Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	store, _, approver := consumeStore(t)
	hash, err := domain.HashExecutionIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	doc, err := approval.Sign(approver, approval.Document{
		SchemaVersion: approval.SchemaVersion, CanonicalVersion: approval.CanonicalVersion, ApprovalID: "approval-consume-1",
		IntentHash: hash, RequesterPrincipal: "operator-alice", ApproverPrincipal: "approver-bob",
		Nonce: hex.EncodeToString(nonce), ValidFrom: intent.ValidFrom, ValidUntil: intent.ValidUntil,
		MaintenanceWindow: intent.MaintenanceWindow, Algorithm: approval.AlgorithmEd25519, KeyID: "key-approver",
	})
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	if err := os.WriteFile(journalPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := audit.Open(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := approval.OpenLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC) }
	result, err := Preflight(t.Context(), inv, intent, store, &doc, clock, journal, ledger, true)
	if err != nil || !result.ApprovalVerified || result.ExecutionReady {
		t.Fatalf("consume failed: %+v %v", result, err)
	}
	if _, err := Preflight(t.Context(), inv, intent, store, &doc, clock, journal, ledger, true); err == nil {
		t.Fatal("replay accepted")
	}
}

func consumeStore(t *testing.T) (approval.TrustStore, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	reqPub, reqPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	apprPub, apprPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return approval.TrustStore{
		Principals: map[string]approval.Principal{
			"operator-alice": {ID: "operator-alice", KeyID: "key-requester", CanRequest: true},
			"approver-bob":   {ID: "approver-bob", KeyID: "key-approver", CanApprove: true},
		},
		Keys:               map[string]ed25519.PublicKey{"key-requester": reqPub, "key-approver": apprPub},
		RevokedApprovalIDs: map[string]bool{},
	}, reqPriv, apprPriv
}
