package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

var (
	ErrInvalid        = errors.New("approval rejected")
	ErrNotYetValid    = errors.New("approval not yet valid")
	ErrExpired        = errors.New("approval expired")
	ErrReplay         = errors.New("approval nonce already consumed")
	ErrWindow         = errors.New("approval outside maintenance window")
	ErrPrincipal      = errors.New("approval principals are not independently trusted")
	ErrSignature      = errors.New("approval signature is invalid")
	ErrIntentMismatch = errors.New("approval is not bound to this execution intent")
	ErrRevoked        = errors.New("approval has been revoked")
)

type Clock func() time.Time

func Verify(store TrustStore, doc Document, intent domain.ExecutionIntent, now time.Time) (*VerifiedApproval, error) {
	if doc.SchemaVersion != SchemaVersion || doc.CanonicalVersion != CanonicalVersion {
		return nil, ErrInvalid
	}
	if doc.Algorithm != AlgorithmEd25519 {
		return nil, ErrSignature
	}
	if !domain.ValidEntityID(doc.ApprovalID) || !nonceValid(doc.Nonce) {
		return nil, ErrInvalid
	}
	intentHash, err := domain.HashExecutionIntent(intent)
	if err != nil {
		return nil, err
	}
	if doc.IntentHash != intentHash {
		return nil, ErrIntentMismatch
	}
	if store.RevokedApprovalIDs[doc.ApprovalID] {
		return nil, ErrRevoked
	}
	requester, ok := store.Principals[doc.RequesterPrincipal]
	if !ok || !requester.CanRequest || !domain.ValidEntityID(doc.RequesterPrincipal) {
		return nil, ErrPrincipal
	}
	approver, ok := store.Principals[doc.ApproverPrincipal]
	if !ok || !approver.CanApprove || !domain.ValidEntityID(doc.ApproverPrincipal) {
		return nil, ErrPrincipal
	}
	if requester.ID == approver.ID || requester.KeyID == approver.KeyID || doc.RequesterPrincipal == doc.ApproverPrincipal {
		return nil, ErrPrincipal
	}
	if intent.RequesterPrincipal != doc.RequesterPrincipal {
		return nil, ErrPrincipal
	}
	if doc.KeyID != approver.KeyID {
		return nil, ErrPrincipal
	}
	pub, ok := store.Keys[doc.KeyID]
	if !ok {
		return nil, ErrSignature
	}
	canonical, err := CanonicalApproval(doc)
	if err != nil {
		return nil, ErrInvalid
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrSignature
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, ErrSignature
	}
	from, err := domain.ParseUTC(doc.ValidFrom)
	if err != nil {
		return nil, err
	}
	until, err := domain.ParseUTC(doc.ValidUntil)
	if err != nil {
		return nil, err
	}
	if now.Before(from) {
		return nil, ErrNotYetValid
	}
	if !now.Before(until) {
		return nil, ErrExpired
	}
	if intent.Limits.MaintenanceWindowRequired {
		if doc.MaintenanceWindow == nil || intent.MaintenanceWindow == nil {
			return nil, ErrWindow
		}
		if doc.MaintenanceWindow.Timezone != intent.MaintenanceWindow.Timezone ||
			doc.MaintenanceWindow.Start != intent.MaintenanceWindow.Start ||
			doc.MaintenanceWindow.End != intent.MaintenanceWindow.End {
			return nil, ErrWindow
		}
		start, err := domain.ParseUTC(doc.MaintenanceWindow.Start)
		if err != nil {
			return nil, err
		}
		end, err := domain.ParseUTC(doc.MaintenanceWindow.End)
		if err != nil {
			return nil, err
		}
		if now.Before(start) || !now.Before(end) {
			return nil, ErrWindow
		}
	}
	return &VerifiedApproval{Document: doc, IntentHash: intentHash}, nil
}
