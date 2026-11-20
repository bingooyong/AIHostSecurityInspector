package audit

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestConsumeAndAuditOnce(t *testing.T) {
	intent := fixtureIntent(t)
	store, _, approver := approvalTestStore(t)
	doc := mustSign(t, intent, approver)
	now := time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC)
	verified, err := approval.Verify(store, doc, intent, now)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	event := Event{EventID: "evt-1", At: now.Format(domain.TimeLayout), Decision: "allow"}
	if err := journal.ConsumeAndAudit(verified, event); err != nil {
		t.Fatal(err)
	}
	if err := journal.ConsumeAndAudit(verified, event); err != approval.ErrReplay {
		t.Fatalf("replay allowed: %v", err)
	}
}

func TestConcurrentConsumeAtMostOnce(t *testing.T) {
	intent := fixtureIntent(t)
	store, _, approver := approvalTestStore(t)
	doc := mustSign(t, intent, approver)
	verified, err := approval.Verify(store, doc, intent, time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- journal.ConsumeAndAudit(verified, Event{EventID: "evt", At: "2026-11-20T01:00:00Z", Decision: "allow"})
		}()
	}
	wg.Wait()
	close(errs)
	allowed, denied := 0, 0
	for err := range errs {
		if err == nil {
			allowed++
		} else {
			denied++
		}
	}
	if allowed != 1 || denied != 1 {
		t.Fatalf("expected one allow and one deny, got allow=%d deny=%d", allowed, denied)
	}
}

func TestJournalRejectsSymlinkAndTruncation(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink journal accepted")
	}
	trunc := filepath.Join(dir, "trunc.jsonl")
	if err := os.WriteFile(trunc, []byte(`{"nonce":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := Open(trunc)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.ConsumeAndAudit(&approval.VerifiedApproval{Document: approval.Document{ApprovalID: "approval-x", Nonce: "aa", RequesterPrincipal: "operator-alice", ApproverPrincipal: "approver-bob"}, IntentHash: "bb"}, Event{EventID: "e", At: "2026-11-20T00:00:00Z", Decision: "allow"}); err == nil {
		t.Fatal("truncated journal accepted")
	}
}
