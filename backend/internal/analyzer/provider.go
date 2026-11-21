package analyzer

import (
	"context"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

type View struct {
	ScanID      string   `json:"scan_id"`
	HostID      string   `json:"host_id"`
	FindingIDs  []string `json:"finding_ids"`
	EvidenceIDs []string `json:"evidence_ids"`
	Redactions  []string `json:"redactions"`
}

type Result struct {
	Status     string             `json:"status"`
	Assessment *domain.Assessment `json:"assessment"`
	Notes      []string           `json:"notes"`
}

type Provider struct {
	Enabled bool
}

func (p Provider) Enrich(ctx context.Context, view View) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !p.Enabled {
		return Result{Status: domain.AIDisabled, Notes: []string{"AI is disabled by default", "untrusted raw logs were not sent"}}, nil
	}
	return Result{Status: domain.AISkipped, Notes: []string{"no approved model endpoint is configured"}}, nil
}

func Minimize(findings []domain.Finding, allowed []string) View {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.FindingID)
	}
	return View{FindingIDs: ids, EvidenceIDs: append([]string{}, allowed...), Redactions: []string{"argv", "environment", "private_key", "password"}}
}
