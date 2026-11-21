package findings

import (
	"fmt"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func FromRuleResults(results []domain.RuleResult, evidence map[string]domain.Evidence, meta map[string]RuleMeta) ([]domain.Finding, error) {
	out := make([]domain.Finding, 0)
	for i, result := range results {
		if result.Outcome != domain.OutcomeFail {
			continue
		}
		info, ok := meta[result.RuleID]
		if !ok {
			return nil, &domain.Error{Code: domain.CodeInvalidID, Message: "finding is missing rule metadata"}
		}
		finding := domain.Finding{
			FindingID:           fmt.Sprintf("finding-%s-%d", result.RuleID, i+1),
			ScanID:              result.ScanID,
			HostID:              result.HostID,
			RuleID:              result.RuleID,
			RuleVersion:         result.RuleVersion,
			Category:            info.Category,
			Severity:            info.Severity,
			Confidence:          info.Confidence,
			Title:               info.Title,
			Description:         info.Description,
			EvidenceRefs:        append([]string{}, result.EvidenceRefs...),
			RemediationGuidance: append([]string{}, info.Remediation...),
			RequiresHumanReview: true,
			ReviewStatus:        domain.ReviewNew,
		}
		if err := domain.ValidateFinding(finding, evidence); err != nil {
			return nil, err
		}
		out = append(out, finding)
	}
	return out, nil
}

type RuleMeta struct {
	Category    string
	Severity    string
	Confidence  int
	Title       string
	Description string
	Remediation []string
}
