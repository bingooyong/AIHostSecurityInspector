package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/analyzer/provider"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

var (
	ErrInvalidOutput  = errors.New("AI output is not a valid structured assessment")
	ErrSeverityChange = errors.New("AI must not change rule severity")
)

type rawAssessment struct {
	OverallAssessment   string        `json:"overall_assessment"`
	Confidence          int           `json:"confidence"`
	RiskLevel           string        `json:"risk_level"`
	Facts               []domain.Fact `json:"facts"`
	Inferences          []domain.Fact `json:"inferences"`
	EvidenceRefs        []string      `json:"evidence_refs"`
	MissingEvidence     []string      `json:"missing_evidence"`
	RecommendedActions  []string      `json:"recommended_actions"`
	Limitations         []string      `json:"limitations"`
	RequiresHumanReview *bool         `json:"requires_human_review"`
}

// Analyze asks the provider for an 11-field assessment. Findings and their
// severities are never taken from the model. Any provider or parse failure
// degrades to AI failed and leaves the deterministic findings untouched.
func Analyze(ctx context.Context, client provider.Client, view View, findings []domain.Finding) (Result, []domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return Result{Status: domain.AIFailed, Notes: []string{"analysis cancelled"}}, findings, err
	}
	preserved := append([]domain.Finding{}, findings...)
	payload, err := json.Marshal(view)
	if err != nil {
		return Result{Status: domain.AIFailed, Notes: []string{"analysis request could not be built"}}, preserved, err
	}
	raw, err := client.Complete(ctx, payload)
	if err != nil {
		status := raw.Status
		if status == "" {
			status = domain.AIFailed
		}
		return Result{Status: status, Notes: append([]string{}, raw.Notes...)}, preserved, nil
	}
	if raw.Status == domain.AIDisabled || raw.Status == domain.AISkipped {
		return Result{Status: raw.Status, Notes: raw.Notes}, preserved, nil
	}
	if raw.Status != domain.AISuccess {
		return Result{Status: domain.AIFailed, Notes: raw.Notes}, preserved, nil
	}
	assessment, err := ParseAssessment(view, raw.Body, preserved)
	if err != nil {
		return Result{Status: domain.AIFailed, Notes: []string{err.Error(), "deterministic findings were preserved"}}, preserved, nil
	}
	return Result{Status: domain.AISuccess, Assessment: &assessment, Notes: raw.Notes}, preserved, nil
}

func ParseAssessment(view View, body []byte, findings []domain.Finding) (domain.Assessment, error) {
	var raw rawAssessment
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return domain.Assessment{}, ErrInvalidOutput
	}
	if raw.RequiresHumanReview == nil || raw.Facts == nil || raw.Inferences == nil || raw.EvidenceRefs == nil || raw.MissingEvidence == nil || raw.RecommendedActions == nil || raw.Limitations == nil {
		return domain.Assessment{}, ErrInvalidOutput
	}
	if raw.OverallAssessment == "" || raw.RiskLevel == "" {
		return domain.Assessment{}, ErrInvalidOutput
	}
	if raw.Confidence < 0 || raw.Confidence > 100 {
		return domain.Assessment{}, ErrInvalidOutput
	}
	if !validOverall(raw.OverallAssessment) || !domain.ValidSeverity(raw.RiskLevel) {
		return domain.Assessment{}, ErrInvalidOutput
	}
	if err := rejectSeverityOverride(body, findings); err != nil {
		return domain.Assessment{}, err
	}
	for _, fact := range raw.Facts {
		if strings.TrimSpace(fact.Statement) == "" || looksLikeInstruction(fact.Statement) {
			return domain.Assessment{}, ErrInvalidOutput
		}
	}
	for _, infer := range raw.Inferences {
		if strings.TrimSpace(infer.Statement) == "" || looksLikeInstruction(infer.Statement) {
			return domain.Assessment{}, ErrInvalidOutput
		}
	}
	review := true
	if raw.RequiresHumanReview != nil {
		review = *raw.RequiresHumanReview
	}
	return domain.Assessment{
		AssessmentID: "assessment-" + view.ScanID, HostID: view.HostID, ScanID: view.ScanID,
		Provider: "hostsec-lab", Model: "structured-v1", PromptVersion: "1.0",
		OverallAssessment: raw.OverallAssessment, Confidence: raw.Confidence, RiskLevel: raw.RiskLevel,
		Facts: raw.Facts, Inferences: raw.Inferences, EvidenceRefs: raw.EvidenceRefs,
		MissingEvidence: raw.MissingEvidence, RecommendedActions: raw.RecommendedActions,
		Limitations: raw.Limitations, RequiresHumanReview: review,
	}, nil
}

func rejectSeverityOverride(body []byte, findings []domain.Finding) error {
	lower := strings.ToLower(string(body))
	for _, finding := range findings {
		if strings.Contains(lower, `"severity"`) && strings.Contains(lower, strings.ToLower(finding.FindingID)) {
			return ErrSeverityChange
		}
	}
	var probe map[string]any
	if err := json.Unmarshal(body, &probe); err != nil {
		return ErrInvalidOutput
	}
	if _, ok := probe["severity"]; ok {
		return ErrSeverityChange
	}
	if _, ok := probe["findings"]; ok {
		return ErrSeverityChange
	}
	return nil
}

func validOverall(v string) bool {
	switch v {
	case domain.AssessmentInsufficient, domain.AssessmentNoFindings, domain.AssessmentSuspicious, domain.AssessmentIncident:
		return true
	}
	return false
}

func looksLikeInstruction(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "ignore previous") || strings.Contains(lower, "<script") || strings.Contains(lower, "os.system")
}
