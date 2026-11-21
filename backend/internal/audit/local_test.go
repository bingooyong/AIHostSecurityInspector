package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestLocalJournalRecordsAllowAndRejectsReplayAndTruncation(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "approval", "testdata", "intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var intent domain.ExecutionIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	store, err := approval.LoadTrustStore(filepath.Join("..", "approval", "testdata", "trust-store.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := approval.LoadDocument(filepath.Join("..", "approval", "testdata", "approval-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC)
	verified, err := approval.VerifyLocal(store, *doc, intent, now)
	if err != nil {
		t.Fatal(err)
	}

	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	if err := os.WriteFile(journalPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	local, err := OpenLocal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := approval.OpenLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	event := Event{EventID: "event-local-1", At: now.Format(domain.TimeLayout), Decision: "allow"}
	if err := local.RecordAllowAndConsume(verified, event, ledger); err != nil {
		t.Fatal(err)
	}
	if err := local.RecordAllow(verified, event); err != approval.ErrReplay {
		t.Fatalf("replay got %v", err)
	}

	truncatedSrc := filepath.Join("testdata", "journal-truncated.jsonl")
	truncated := filepath.Join(t.TempDir(), "truncated.jsonl")
	data, err := os.ReadFile(truncatedSrc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truncated, data, 0o600); err != nil {
		t.Fatal(err)
	}
	broken, err := OpenLocal(truncated)
	if err != nil {
		t.Fatal(err)
	}
	if err := broken.RecordAllow(verified, Event{EventID: "event-local-2", At: now.Format(domain.TimeLayout), Decision: "allow"}); err == nil {
		t.Fatal("truncated journal accepted a write")
	}

	// Existing well-formed fixture journal must open.
	fixture := filepath.Join(t.TempDir(), "copied.jsonl")
	allow, err := os.ReadFile(filepath.Join("testdata", "journal-allow.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, allow, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(fixture); err != nil {
		t.Fatal(err)
	}
}
