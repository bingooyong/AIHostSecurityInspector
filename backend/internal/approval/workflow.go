package approval

import (
	"crypto/ed25519"
	"errors"
	"sync"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const (
	RequestPending  = "pending"
	RequestGranted  = "granted"
	RequestDenied   = "denied"
	RequestConsumed = "consumed"
)

var ErrSelfApprove = errors.New("requester cannot approve their own request")

type Request struct {
	RequestID          string `json:"request_id"`
	PlanID             string `json:"plan_id"`
	IntentHash         string `json:"intent_hash"`
	RequesterPrincipal string `json:"requester_principal"`
	Reason             string `json:"reason"`
	Status             string `json:"status"`
	ApprovalID         string `json:"approval_id,omitempty"`
}

type Workflow struct {
	mu       sync.Mutex
	requests map[string]Request
}

func NewWorkflow() *Workflow {
	return &Workflow{requests: map[string]Request{}}
}

func (w *Workflow) Request(requestID, planID, intentHash, requester, reason string) (Request, error) {
	if !domain.ValidEntityID(requestID) || !domain.ValidEntityID(planID) || !domain.ValidEntityID(requester) {
		return Request{}, ErrInvalid
	}
	if reason == "" {
		return Request{}, ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.requests[requestID]; ok {
		return Request{}, errors.New("approval request already exists")
	}
	rec := Request{
		RequestID: requestID, PlanID: planID, IntentHash: intentHash,
		RequesterPrincipal: requester, Reason: reason, Status: RequestPending,
	}
	w.requests[requestID] = rec
	return rec, nil
}

func (w *Workflow) Grant(requestID, approver string, store TrustStore, intent domain.ExecutionIntent, doc Document, now Clock, private ed25519.PrivateKey) (Request, Document, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec, ok := w.requests[requestID]
	if !ok || rec.Status != RequestPending {
		return Request{}, Document{}, ErrInvalid
	}
	if approver == rec.RequesterPrincipal {
		return Request{}, Document{}, ErrSelfApprove
	}
	principal, ok := store.Principals[approver]
	if !ok || !principal.CanApprove {
		return Request{}, Document{}, ErrPrincipal
	}
	if doc.RequesterPrincipal != rec.RequesterPrincipal || doc.ApproverPrincipal != approver {
		return Request{}, Document{}, ErrPrincipal
	}
	if doc.IntentHash != rec.IntentHash {
		return Request{}, Document{}, ErrIntentMismatch
	}
	signed, err := Sign(private, doc)
	if err != nil {
		return Request{}, Document{}, err
	}
	if _, err := Verify(store, signed, intent, now()); err != nil {
		return Request{}, Document{}, err
	}
	rec.Status = RequestGranted
	rec.ApprovalID = signed.ApprovalID
	w.requests[requestID] = rec
	return rec, signed, nil
}

func (w *Workflow) MarkConsumed(requestID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec, ok := w.requests[requestID]
	if !ok || rec.Status != RequestGranted {
		return ErrInvalid
	}
	rec.Status = RequestConsumed
	w.requests[requestID] = rec
	return nil
}

func (w *Workflow) Get(requestID string) (Request, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec, ok := w.requests[requestID]
	if !ok {
		return Request{}, ErrInvalid
	}
	return rec, nil
}
