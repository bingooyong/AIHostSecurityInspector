package collector

import (
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const Version = "0.1.0"

type Limits struct {
	Timeout    time.Duration
	MaxRecords int
	MaxBytes   int64
}

// Request is the SDD Collect contract: identities, module, profile, policy and
// limits only. It never carries a command, SQL, script, or raw environment.
type Request struct {
	ScanID        string
	AttemptID     string
	HostID        string
	ModuleID      string
	Profile       string
	PolicyVersion string
	Limits        Limits
}

type Result struct {
	ModuleID     string           `json:"module_id"`
	Version      string           `json:"version"`
	StartedAt    string           `json:"started_at"`
	EndedAt      string           `json:"ended_at"`
	Status       string           `json:"status"`
	Completeness string           `json:"completeness"`
	Records      []map[string]any `json:"records"`
	RawRefs      []string         `json:"raw_evidence_refs"`
	Warnings     []string         `json:"warnings"`
	ErrorCode    string           `json:"error_code,omitempty"`
}

func (r Request) Validate() error {
	if !domain.ValidEntityID(r.ScanID) || !domain.ValidEntityID(r.AttemptID) || !domain.ValidHostID(r.HostID) {
		return &domain.Error{Code: domain.CodeInvalidID, Message: "collection request identity is invalid"}
	}
	if !domain.ValidEntityID(r.ModuleID) || !domain.ValidProfile(r.Profile) || !domain.ValidVersion(r.PolicyVersion) {
		return &domain.Error{Code: domain.CodeInvalidID, Message: "collection module fields are invalid"}
	}
	if r.Limits.MaxRecords < 0 || r.Limits.MaxBytes < 0 || r.Limits.Timeout < 0 {
		return &domain.Error{Code: domain.CodeInvalidCanonical, Message: "collection limits are invalid"}
	}
	return nil
}
