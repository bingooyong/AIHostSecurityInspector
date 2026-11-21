package approval

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestWorkflowRequestIsNotAGrantAndRejectsSelfApprove(t *testing.T) {
	intent := fixtureIntent(t, domain.ProfileDeep)
	store, _, approver := testStore(t)
	hash, err := domain.HashExecutionIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	flow := NewWorkflow()
	rec, err := flow.Request("request-deep-1", "plan-deep-1", hash, "operator-alice", "need deep inspect")
	if err != nil || rec.Status != RequestPending || rec.ApprovalID != "" {
		t.Fatalf("request granted itself: %+v %v", rec, err)
	}
	nonce := make([]byte, 32)
	doc := Document{
		SchemaVersion: SchemaVersion, CanonicalVersion: CanonicalVersion, ApprovalID: "approval-flow-1",
		IntentHash: hash, RequesterPrincipal: "operator-alice", ApproverPrincipal: "approver-bob",
		Nonce: hex.EncodeToString(nonce), ValidFrom: intent.ValidFrom, ValidUntil: intent.ValidUntil,
		MaintenanceWindow: intent.MaintenanceWindow, Algorithm: AlgorithmEd25519, KeyID: "key-approver",
	}
	clock := func() time.Time { return time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC) }
	if _, _, err := flow.Grant("request-deep-1", "operator-alice", store, intent, doc, clock, approver); err == nil {
		t.Fatal("self-approve accepted")
	}
	granted, signed, err := flow.Grant("request-deep-1", "approver-bob", store, intent, doc, clock, approver)
	if err != nil || granted.Status != RequestGranted || signed.Signature == "" {
		t.Fatal(err, granted)
	}
	listed := flow.List()
	if len(listed) != 1 || listed[0].RequestID != "request-deep-1" || listed[0].Status != RequestGranted {
		t.Fatalf("list: %+v", listed)
	}
}
