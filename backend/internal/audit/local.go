package audit

import (
	"errors"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
)

// Local is the file-backed append-only audit journal used by HOSTSEC-32A.
// It is not a platform audit service.
type Local struct {
	*Journal
}

func OpenLocal(path string) (*Local, error) {
	journal, err := Open(path)
	if err != nil {
		return nil, err
	}
	return &Local{Journal: journal}, nil
}

func (l *Local) RecordAllow(verified *approval.VerifiedApproval, event Event) error {
	if l == nil || l.Journal == nil {
		return errors.New("audit journal is required")
	}
	return l.ConsumeAndAudit(verified, event)
}

func (l *Local) RecordAllowAndConsume(verified *approval.VerifiedApproval, event Event, ledger *approval.Ledger) error {
	if err := l.RecordAllow(verified, event); err != nil {
		return err
	}
	if ledger == nil {
		return approval.ErrInvalid
	}
	return ledger.Consume(verified.Document.Nonce)
}
