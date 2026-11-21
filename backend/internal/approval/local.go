package approval

import (
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

// LocalVerifier is the file-backed local approval verifier for HOSTSEC-32A.
// It is not a platform identity provider or hosted approval service.
type LocalVerifier struct {
	Store  TrustStore
	Ledger *Ledger
	Now    func() time.Time
}

func OpenLocal(storePath, ledgerPath string, now func() time.Time) (*LocalVerifier, error) {
	store, err := LoadTrustStore(storePath)
	if err != nil {
		return nil, err
	}
	var ledger *Ledger
	if ledgerPath != "" {
		ledger, err = OpenLedger(ledgerPath)
		if err != nil {
			return nil, err
		}
	}
	if now == nil {
		now = time.Now
	}
	return &LocalVerifier{Store: store, Ledger: ledger, Now: now}, nil
}

func (v *LocalVerifier) clock() time.Time {
	if v != nil && v.Now != nil {
		return v.Now()
	}
	return time.Now().UTC()
}

func VerifyLocal(store TrustStore, doc Document, intent domain.ExecutionIntent, now time.Time) (*VerifiedApproval, error) {
	return Verify(store, doc, intent, now)
}

func (v *LocalVerifier) VerifyDocument(doc Document, intent domain.ExecutionIntent) (*VerifiedApproval, error) {
	if v == nil {
		return nil, ErrInvalid
	}
	return Verify(v.Store, doc, intent, v.clock())
}

func (v *LocalVerifier) VerifyFile(documentPath string, intent domain.ExecutionIntent) (*VerifiedApproval, error) {
	doc, err := LoadDocument(documentPath)
	if err != nil {
		return nil, err
	}
	return v.VerifyDocument(*doc, intent)
}

func (v *LocalVerifier) Consume(verified *VerifiedApproval) error {
	if v == nil || verified == nil {
		return ErrInvalid
	}
	if v.Ledger == nil {
		return ErrInvalid
	}
	return v.Ledger.Consume(verified.Document.Nonce)
}
