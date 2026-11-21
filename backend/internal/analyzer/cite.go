package analyzer

import (
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func ValidateCitations(view View, assessment domain.Assessment, evidence map[string]domain.Evidence) error {
	allowed := map[string]struct{}{}
	for _, id := range view.EvidenceIDs {
		allowed[id] = struct{}{}
	}
	for _, ref := range assessment.EvidenceRefs {
		if _, ok := allowed[ref]; !ok {
			return &domain.Error{Code: domain.CodeUnknownEvidence, Message: "AI cited evidence outside the minimized view"}
		}
		ev, ok := evidence[ref]
		if !ok || !ev.SupportsDetection() {
			return &domain.Error{Code: domain.CodeEvidenceUnusable, Message: "AI cited unusable evidence"}
		}
	}
	return nil
}
