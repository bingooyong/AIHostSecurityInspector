package evidence

import (
	"crypto/ed25519"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/sign"
)

type unsignedManifest struct {
	SchemaVersion    string          `json:"schema_version"`
	ScanID           string          `json:"scan_id"`
	HostIDs          []string        `json:"host_ids"`
	AttemptIDs       []string        `json:"attempt_ids"`
	CreatedAt        string          `json:"created_at"`
	Producer         string          `json:"producer"`
	CollectorVersion string          `json:"collector_version"`
	PolicyVersion    string          `json:"policy_version"`
	SignatureNote    string          `json:"signature_note"`
	Entries          []ManifestEntry `json:"entries"`
}

func CanonicalManifest(man Manifest) ([]byte, error) {
	return sign.Canonical(unsignedManifest{
		SchemaVersion: man.SchemaVersion, ScanID: man.ScanID, HostIDs: man.HostIDs,
		AttemptIDs: man.AttemptIDs, CreatedAt: man.CreatedAt, Producer: man.Producer,
		CollectorVersion: man.CollectorVersion, PolicyVersion: man.PolicyVersion,
		SignatureNote: man.SignatureNote, Entries: man.Entries,
	})
}

func (m *Manifest) Sign(private ed25519.PrivateKey) error {
	m.SignatureNote = "ed25519 covers canonical manifest bytes; it is not host source authenticity"
	canonical, err := CanonicalManifest(*m)
	if err != nil {
		return err
	}
	sig, err := sign.Sign(private, canonical)
	if err != nil {
		return err
	}
	m.Signature = &sig
	return nil
}

func (m Manifest) VerifySignature(public ed25519.PublicKey) error {
	if m.Signature == nil || *m.Signature == "" {
		return sign.ErrSignature
	}
	canonical, err := CanonicalManifest(m)
	if err != nil {
		return err
	}
	return sign.Verify(public, canonical, *m.Signature)
}
