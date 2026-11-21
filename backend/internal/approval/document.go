package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const (
	SchemaVersion    = "1.0"
	CanonicalVersion = "approval-canonical-v1"
	AlgorithmEd25519 = "ed25519"
)

type Principal struct {
	ID         string `json:"id"`
	KeyID      string `json:"key_id"`
	CanRequest bool   `json:"can_request"`
	CanApprove bool   `json:"can_approve"`
}

type TrustStore struct {
	Principals         map[string]Principal
	Keys               map[string]ed25519.PublicKey
	RevokedApprovalIDs map[string]bool
}

type Document struct {
	SchemaVersion      string                    `json:"schema_version"`
	CanonicalVersion   string                    `json:"canonical_version"`
	ApprovalID         string                    `json:"approval_id"`
	IntentHash         string                    `json:"intent_hash"`
	RequesterPrincipal string                    `json:"requester_principal"`
	ApproverPrincipal  string                    `json:"approver_principal"`
	Nonce              string                    `json:"nonce"`
	ValidFrom          string                    `json:"valid_from"`
	ValidUntil         string                    `json:"valid_until"`
	MaintenanceWindow  *domain.MaintenanceWindow `json:"maintenance_window"`
	Algorithm          string                    `json:"algorithm"`
	KeyID              string                    `json:"key_id"`
	Signature          string                    `json:"signature"`
}

type signedPayload struct {
	SchemaVersion      string                    `json:"schema_version"`
	CanonicalVersion   string                    `json:"canonical_version"`
	ApprovalID         string                    `json:"approval_id"`
	IntentHash         string                    `json:"intent_hash"`
	RequesterPrincipal string                    `json:"requester_principal"`
	ApproverPrincipal  string                    `json:"approver_principal"`
	Nonce              string                    `json:"nonce"`
	ValidFrom          string                    `json:"valid_from"`
	ValidUntil         string                    `json:"valid_until"`
	MaintenanceWindow  *domain.MaintenanceWindow `json:"maintenance_window"`
	Algorithm          string                    `json:"algorithm"`
	KeyID              string                    `json:"key_id"`
}

type VerifiedApproval struct {
	Document   Document
	IntentHash string
}

func CanonicalApproval(doc Document) ([]byte, error) {
	payload, err := json.Marshal(signedPayload{
		SchemaVersion:      doc.SchemaVersion,
		CanonicalVersion:   doc.CanonicalVersion,
		ApprovalID:         doc.ApprovalID,
		IntentHash:         doc.IntentHash,
		RequesterPrincipal: doc.RequesterPrincipal,
		ApproverPrincipal:  doc.ApproverPrincipal,
		Nonce:              doc.Nonce,
		ValidFrom:          doc.ValidFrom,
		ValidUntil:         doc.ValidUntil,
		MaintenanceWindow:  doc.MaintenanceWindow,
		Algorithm:          doc.Algorithm,
		KeyID:              doc.KeyID,
	})
	if err != nil {
		return nil, err
	}
	out := append([]byte(CanonicalVersion+"\n"), payload...)
	return out, nil
}

func Sign(private ed25519.PrivateKey, doc Document) (Document, error) {
	canonical, err := CanonicalApproval(doc)
	if err != nil {
		return Document{}, err
	}
	doc.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	return doc, nil
}

func nonceValid(v string) bool {
	raw, err := hex.DecodeString(v)
	return err == nil && len(raw) == 32
}
