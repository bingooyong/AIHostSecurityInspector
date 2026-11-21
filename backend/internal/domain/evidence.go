package domain

type Evidence struct {
	EvidenceID       string         `json:"evidence_id"`
	HostID           string         `json:"host_id"`
	ScanID           string         `json:"scan_id"`
	AttemptID        string         `json:"attempt_id"`
	CollectedAt      string         `json:"collected_at"`
	ReceivedAt       string         `json:"received_at"`
	Module           string         `json:"module"`
	CollectorVersion string         `json:"collector_version"`
	Category         string         `json:"category"`
	RawSummary       string         `json:"raw_summary"`
	RawRef           *string        `json:"raw_ref"`
	NormalizedData   map[string]any `json:"normalized_data"`
	SHA256           *string        `json:"sha256"`
	NormalizedSHA256 *string        `json:"normalized_sha256"`
	CollectionStatus string         `json:"collection_status"`
	IntegrityStatus  string         `json:"integrity_status"`
	Completeness     string         `json:"completeness"`
	Warnings         []string       `json:"warnings"`
}

type RuleResult struct {
	RuleID          string   `json:"rule_id"`
	RuleVersion     string   `json:"rule_version"`
	ScanID          string   `json:"scan_id"`
	HostID          string   `json:"host_id"`
	Outcome         string   `json:"outcome"`
	EvidenceRefs    []string `json:"evidence_refs"`
	MissingEvidence []string `json:"missing_evidence"`
	ReasonCode      string   `json:"reason_code"`
	BaselineRef     *string  `json:"baseline_ref"`
}

type Finding struct {
	FindingID           string   `json:"finding_id"`
	ScanID              string   `json:"scan_id"`
	HostID              string   `json:"host_id"`
	RuleID              string   `json:"rule_id"`
	RuleVersion         string   `json:"rule_version"`
	Category            string   `json:"category"`
	Severity            string   `json:"severity"`
	Confidence          int      `json:"confidence"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	EvidenceRefs        []string `json:"evidence_refs"`
	RemediationGuidance []string `json:"remediation_guidance"`
	RequiresHumanReview bool     `json:"requires_human_review"`
	ReviewStatus        string   `json:"review_status"`
}

type Fact struct {
	Statement    string   `json:"statement"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type Assessment struct {
	AssessmentID        string   `json:"assessment_id"`
	HostID              string   `json:"host_id"`
	ScanID              string   `json:"scan_id"`
	Provider            string   `json:"provider"`
	Model               string   `json:"model"`
	PromptVersion       string   `json:"prompt_version"`
	OverallAssessment   string   `json:"overall_assessment"`
	Confidence          int      `json:"confidence"`
	RiskLevel           string   `json:"risk_level"`
	Facts               []Fact   `json:"facts"`
	Inferences          []Fact   `json:"inferences"`
	EvidenceRefs        []string `json:"evidence_refs"`
	MissingEvidence     []string `json:"missing_evidence"`
	RecommendedActions  []string `json:"recommended_actions"`
	Limitations         []string `json:"limitations"`
	RequiresHumanReview bool     `json:"requires_human_review"`
}

func hashPtrValid(v *string) bool {
	return v != nil && ValidSHA256(*v)
}

func (e Evidence) SupportsDetection() bool {
	return e.CollectionStatus == CollectionSuccess &&
		e.Completeness == CompletenessComplete &&
		e.IntegrityStatus == IntegrityVerified &&
		hashPtrValid(e.SHA256) &&
		hashPtrValid(e.NormalizedSHA256)
}

func (e Evidence) SupportsCollectionFailure() bool {
	switch e.CollectionStatus {
	case CollectionFailed, CollectionTimeout, CollectionCancelled, CollectionNotAvailable, CollectionPartial:
		return true
	}
	return false
}

func (e Evidence) Validate() error {
	if !ValidEntityID(e.EvidenceID) || !ValidHostID(e.HostID) || !ValidEntityID(e.ScanID) || !ValidEntityID(e.AttemptID) {
		return fail(CodeInvalidID, "evidence identity is invalid")
	}
	if err := requireOrder(e.CollectedAt, e.ReceivedAt, true); err != nil {
		return err
	}
	if !ValidEntityID(e.Module) || !ValidVersion(e.CollectorVersion) || !ValidEntityID(e.Category) {
		return fail(CodeInvalidID, "evidence module fields are invalid")
	}
	if !validSafeText(e.RawSummary, 1, 4000) {
		return fail(CodeInvalidCanonical, "raw_summary is invalid")
	}
	if e.RawRef != nil && (len(*e.RawRef) == 0 || len(*e.RawRef) > 1024) {
		return fail(CodeInvalidCanonical, "raw_ref is invalid")
	}
	if e.NormalizedData == nil || len(e.NormalizedData) > 1000 {
		return fail(CodeInvalidCanonical, "normalized_data is invalid")
	}
	if !ValidCollectionStatus(e.CollectionStatus) || !ValidIntegrity(e.IntegrityStatus) || !ValidCompleteness(e.Completeness) {
		return fail(CodeInvalidEnum, "evidence status enum is invalid")
	}
	if e.Warnings == nil || len(e.Warnings) > 200 || !uniqueNonEmpty(e.Warnings, func(s string) bool { return validSafeText(s, 1, 4000) }) && len(e.Warnings) != 0 {
		if e.Warnings == nil {
			return fail(CodeInvalidCanonical, "warnings must be an array")
		}
		if len(e.Warnings) > 200 {
			return fail(CodeInvalidCanonical, "warnings exceed bound")
		}
		for _, w := range e.Warnings {
			if !validSafeText(w, 1, 4000) {
				return fail(CodeInvalidCanonical, "warning text is invalid")
			}
		}
	}
	if e.SHA256 != nil && !ValidSHA256(*e.SHA256) {
		return fail(CodeInvalidCanonical, "sha256 is invalid")
	}
	if e.NormalizedSHA256 != nil && !ValidSHA256(*e.NormalizedSHA256) {
		return fail(CodeInvalidCanonical, "normalized_sha256 is invalid")
	}
	if e.IntegrityStatus == IntegrityVerified && (!hashPtrValid(e.SHA256) || !hashPtrValid(e.NormalizedSHA256)) {
		return fail(CodeInvalidCanonical, "verified integrity requires hashes")
	}
	if e.CollectionStatus == CollectionSuccess {
		if e.Completeness != CompletenessComplete || !hashPtrValid(e.SHA256) || !hashPtrValid(e.NormalizedSHA256) {
			return fail(CodeInvalidCanonical, "successful collection requires complete hashed evidence")
		}
	}
	return nil
}

func (r RuleResult) Validate() error {
	if !ValidEntityID(r.RuleID) || !ValidVersion(r.RuleVersion) || !ValidEntityID(r.ScanID) || !ValidHostID(r.HostID) {
		return fail(CodeInvalidID, "rule result identity is invalid")
	}
	if !ValidOutcome(r.Outcome) {
		return fail(CodeInvalidEnum, "rule outcome is invalid")
	}
	if !ValidEntityID(r.ReasonCode) {
		return fail(CodeInvalidID, "reason_code is invalid")
	}
	if r.EvidenceRefs == nil || !uniqueNonEmpty(r.EvidenceRefs, ValidEntityID) && len(r.EvidenceRefs) != 0 {
		if r.EvidenceRefs == nil {
			return fail(CodeInvalidID, "evidence_refs must be an array")
		}
		if !uniqueNonEmpty(r.EvidenceRefs, ValidEntityID) {
			return fail(CodeInvalidID, "evidence_refs are invalid")
		}
	}
	if r.MissingEvidence == nil {
		return fail(CodeInvalidCanonical, "missing_evidence must be an array")
	}
	for _, item := range r.MissingEvidence {
		if !validSafeText(item, 1, 4000) {
			return fail(CodeInvalidCanonical, "missing_evidence text is invalid")
		}
	}
	if r.BaselineRef != nil && !ValidEntityID(*r.BaselineRef) {
		return fail(CodeInvalidID, "baseline_ref is invalid")
	}
	switch r.Outcome {
	case OutcomePass, OutcomeFail:
		if len(r.EvidenceRefs) == 0 {
			return fail(CodeEvidenceUnusable, "PASS/FAIL requires evidence")
		}
		if len(r.MissingEvidence) != 0 {
			return fail(CodeEvidenceUnusable, "PASS/FAIL cannot record missing evidence")
		}
	case OutcomeUnknown:
		if len(r.MissingEvidence) == 0 && len(r.EvidenceRefs) == 0 {
			return fail(CodeEvidenceUnusable, "UNKNOWN requires missing evidence or supporting collection evidence")
		}
	}
	return nil
}

func (f Finding) Validate() error {
	if !ValidEntityID(f.FindingID) || !ValidEntityID(f.ScanID) || !ValidHostID(f.HostID) || !ValidEntityID(f.RuleID) || !ValidVersion(f.RuleVersion) || !ValidEntityID(f.Category) {
		return fail(CodeInvalidID, "finding identity is invalid")
	}
	if !ValidSeverity(f.Severity) || !ValidReviewStatus(f.ReviewStatus) {
		return fail(CodeInvalidEnum, "finding enum is invalid")
	}
	if f.Confidence < 0 || f.Confidence > 100 {
		return fail(CodeInvalidCanonical, "confidence is out of range")
	}
	if !validSafeText(f.Title, 1, MaxShortText) || !validSafeText(f.Description, 1, MaxTextLen) {
		return fail(CodeInvalidCanonical, "finding text is invalid")
	}
	if len(f.EvidenceRefs) == 0 || !uniqueNonEmpty(f.EvidenceRefs, ValidEntityID) {
		return fail(CodeEvidenceUnusable, "finding requires evidence refs")
	}
	if f.RemediationGuidance == nil {
		return fail(CodeInvalidCanonical, "remediation_guidance must be an array")
	}
	for _, item := range f.RemediationGuidance {
		if !validSafeText(item, 1, 4000) {
			return fail(CodeInvalidCanonical, "remediation text is invalid")
		}
	}
	if !f.RequiresHumanReview {
		return fail(CodeInvalidCanonical, "findings require human review")
	}
	return nil
}

func (a Assessment) Validate() error {
	if !ValidEntityID(a.AssessmentID) || !ValidHostID(a.HostID) || !ValidEntityID(a.ScanID) {
		return fail(CodeInvalidID, "assessment identity is invalid")
	}
	if !validSafeText(a.Provider, 1, 128) || !validSafeText(a.Model, 1, 128) || !ValidVersion(a.PromptVersion) {
		return fail(CodeInvalidID, "assessment provider fields are invalid")
	}
	switch a.OverallAssessment {
	case AssessmentInsufficient, AssessmentNoFindings, AssessmentSuspicious, AssessmentIncident:
	default:
		return fail(CodeInvalidEnum, "overall_assessment is invalid")
	}
	if a.Confidence < 0 || a.Confidence > 100 {
		return fail(CodeInvalidCanonical, "confidence is out of range")
	}
	if a.RiskLevel != "unknown" && !ValidSeverity(a.RiskLevel) {
		return fail(CodeInvalidEnum, "risk_level is invalid")
	}
	if a.Facts == nil || a.Inferences == nil || a.EvidenceRefs == nil || a.MissingEvidence == nil || a.RecommendedActions == nil || a.Limitations == nil {
		return fail(CodeInvalidCanonical, "assessment arrays are required")
	}
	if !uniqueNonEmpty(a.EvidenceRefs, ValidEntityID) && len(a.EvidenceRefs) != 0 {
		return fail(CodeInvalidID, "assessment evidence_refs are invalid")
	}
	if !a.RequiresHumanReview {
		return fail(CodeInvalidCanonical, "assessment requires human review")
	}
	for _, fact := range append(append([]Fact{}, a.Facts...), a.Inferences...) {
		if !validSafeText(fact.Statement, 1, 4000) || len(fact.EvidenceRefs) == 0 || !uniqueNonEmpty(fact.EvidenceRefs, ValidEntityID) {
			return fail(CodeInvalidCanonical, "assessment statement is invalid")
		}
	}
	return nil
}
