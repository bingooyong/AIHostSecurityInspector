package risk

import (
	"errors"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const (
	KindFalsePositive = "false_positive"
	KindRemediation   = "remediation"
	KindRescan        = "rescan"
)

var (
	ErrFirstScanChange = errors.New("first scan cannot report a change")
	ErrAutoRemediation = errors.New("automatic remediation is not permitted")
	ErrUnknownKind     = errors.New("review kind is invalid")
)

type Link struct {
	FindingID     string `json:"finding_id"`
	Kind          string `json:"kind"`
	RelatedScanID string `json:"related_scan_id"`
	HostID        string `json:"host_id"`
	Note          string `json:"note"`
}

type Change struct {
	FindingID string `json:"finding_id"`
	HostID    string `json:"host_id"`
	Kind      string `json:"kind"`
}

func LinkReview(link Link) error {
	if !domain.ValidEntityID(link.FindingID) || !domain.ValidEntityID(link.RelatedScanID) || !domain.ValidHostID(link.HostID) {
		return &domain.Error{Code: domain.CodeInvalidID, Message: "review link identifiers are invalid"}
	}
	switch link.Kind {
	case KindFalsePositive, KindRemediation, KindRescan:
	default:
		return ErrUnknownKind
	}
	if link.Kind == KindRemediation && link.Note == "auto" {
		return ErrAutoRemediation
	}
	return nil
}

func Trend(previous, current []domain.Finding, firstScan bool) ([]Change, error) {
	if firstScan {
		if len(previous) != 0 {
			return nil, ErrFirstScanChange
		}
		return []Change{}, nil
	}
	prev := map[string]domain.Finding{}
	for _, finding := range previous {
		prev[finding.RuleID+"/"+finding.HostID] = finding
	}
	out := make([]Change, 0)
	for _, finding := range current {
		if finding.HostID == "" || finding.ScanID == "" {
			return nil, &domain.Error{Code: domain.CodeInvalidID, Message: "trend finding is missing host or scan"}
		}
		key := finding.RuleID + "/" + finding.HostID
		before, ok := prev[key]
		if !ok {
			out = append(out, Change{FindingID: finding.FindingID, HostID: finding.HostID, Kind: "new"})
			continue
		}
		if before.ReviewStatus != finding.ReviewStatus {
			out = append(out, Change{FindingID: finding.FindingID, HostID: finding.HostID, Kind: "review_status"})
		}
		delete(prev, key)
	}
	for _, finding := range prev {
		out = append(out, Change{FindingID: finding.FindingID, HostID: finding.HostID, Kind: "absent"})
	}
	return out, nil
}
