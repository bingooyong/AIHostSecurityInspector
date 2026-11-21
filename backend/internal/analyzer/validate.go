package analyzer

import (
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

// ValidateAssessment requires every conclusion to cite the same scan/host and
// only evidence IDs that were in the minimized allow-list.
func ValidateAssessment(view View, assessment domain.Assessment, evidence map[string]domain.Evidence) error {
	if assessment.ScanID != view.ScanID || assessment.HostID != view.HostID {
		return &domain.Error{Code: domain.CodeUnknownEvidence, Message: "assessment host or scan does not match the allowed view"}
	}
	if len(assessment.EvidenceRefs) == 0 && len(assessment.MissingEvidence) == 0 {
		return &domain.Error{Code: domain.CodeUnknownEvidence, Message: "assessment has no evidence refs or missing evidence"}
	}
	if err := ValidateCitations(view, assessment, evidence); err != nil {
		return err
	}
	for _, fact := range append(append([]domain.Fact{}, assessment.Facts...), assessment.Inferences...) {
		for _, ref := range fact.EvidenceRefs {
			if !containsID(view.EvidenceIDs, ref) {
				return &domain.Error{Code: domain.CodeUnknownEvidence, Message: "fact cited evidence outside the minimized view"}
			}
			ev, ok := evidence[ref]
			if !ok || ev.HostID != view.HostID || ev.ScanID != view.ScanID || !ev.SupportsDetection() {
				return &domain.Error{Code: domain.CodeEvidenceUnusable, Message: "fact cited evidence from another host or scan"}
			}
		}
	}
	return nil
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
