package audit

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
)

const SchemaVersion = "1.0"

type Event struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`
	At            string `json:"at"`
	Decision      string `json:"decision"`
	ApprovalID    string `json:"approval_id"`
	IntentHash    string `json:"intent_hash"`
	Nonce         string `json:"nonce"`
	Requester     string `json:"requester_principal"`
	Approver      string `json:"approver_principal"`
	Reason        string `json:"reason,omitempty"`
}

type Journal struct {
	path string
}

func Open(path string) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("cannot open audit journal")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("audit journal must be a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("audit journal permissions are too open")
	}
	return &Journal{path: path}, nil
}

func (j *Journal) ConsumeAndAudit(verified *approval.VerifiedApproval, event Event) error {
	if verified == nil {
		return errors.New("missing verified approval")
	}
	if event.Decision != "allow" {
		return errors.New("consume requires an allow decision")
	}
	event.SchemaVersion = SchemaVersion
	event.ApprovalID = verified.Document.ApprovalID
	event.IntentHash = verified.IntentHash
	event.Nonce = verified.Document.Nonce
	event.Requester = verified.Document.RequesterPrincipal
	event.Approver = verified.Document.ApproverPrincipal
	f, err := os.OpenFile(j.path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("cannot lock audit journal")
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return errors.New("cannot lock audit journal")
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	data, err := io.ReadAll(f)
	if err != nil {
		return errors.New("cannot read audit journal")
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return errors.New("audit journal is truncated")
	}
	seen := map[string]bool{}
	start := 0
	for i, b := range data {
		if b != '\n' {
			continue
		}
		line := data[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var existing Event
		if err := json.Unmarshal(line, &existing); err != nil {
			return errors.New("audit journal is corrupt")
		}
		if existing.Nonce != "" {
			seen[existing.Nonce] = true
		}
	}
	if seen[event.Nonce] {
		return approval.ErrReplay
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return errors.New("cannot encode audit event")
	}
	payload = append(payload, '\n')
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return errors.New("cannot append audit journal")
	}
	if _, err := f.Write(payload); err != nil {
		return errors.New("cannot append audit journal")
	}
	if err := f.Sync(); err != nil {
		return errors.New("cannot persist audit journal")
	}
	return nil
}
