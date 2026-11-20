package domain

type Coverage struct {
	TotalModules int      `json:"total_modules"`
	Succeeded    int      `json:"succeeded"`
	Failed       int      `json:"failed"`
	Skipped      int      `json:"skipped"`
	Coverage     *float64 `json:"coverage"`
}

type HumanReview struct {
	Status string   `json:"status"`
	Notes  []string `json:"notes"`
}

// ScanSnapshot is an in-memory relationship graph. It is not a filesystem or SQL handle.
type ScanSnapshot struct {
	SchemaVersion      string        `json:"schema_version"`
	Job                ScanJob       `json:"job"`
	Attempts           []ScanAttempt `json:"attempts"`
	Evidence           []Evidence    `json:"evidence"`
	RuleResults        []RuleResult  `json:"rule_results"`
	Findings           []Finding     `json:"findings"`
	Assessment         *Assessment   `json:"assessment"`
	CollectionSummary  Coverage      `json:"collection_summary"`
	Limitations        []string      `json:"limitations"`
	HumanReview        HumanReview   `json:"human_review"`
	AllowedEvidenceIDs []string      `json:"-"`
}

func ValidateSnapshot(snapshot ScanSnapshot) error {
	if snapshot.SchemaVersion != SchemaV1 {
		return fail(CodeSchemaVersionUnsupported, "unsupported snapshot schema version")
	}
	if err := snapshot.Job.Validate(); err != nil {
		return err
	}
	hosts := map[string]struct{}{}
	for _, id := range snapshot.Job.HostIDs {
		hosts[id] = struct{}{}
	}
	attemptIDs := map[string]ScanAttempt{}
	for _, attempt := range snapshot.Attempts {
		if err := attempt.Validate(); err != nil {
			return err
		}
		if attempt.ScanID != snapshot.Job.ScanID {
			return fail(CodeCrossScopeReference, "attempt is outside this scan")
		}
		if _, ok := hosts[attempt.HostID]; !ok {
			return fail(CodeCrossScopeReference, "attempt host is outside this scan")
		}
		if _, exists := attemptIDs[attempt.AttemptID]; exists {
			return fail(CodeDuplicateID, "attempt_id is duplicated")
		}
		if attempt.RetryOf != "" {
			if _, ok := attemptIDs[attempt.RetryOf]; !ok {
				return fail(CodeInvalidReference, "retry_of does not refer to an earlier attempt")
			}
		}
		attemptIDs[attempt.AttemptID] = attempt
	}
	evidenceByID := map[string]Evidence{}
	for _, ev := range snapshot.Evidence {
		if err := ev.Validate(); err != nil {
			return err
		}
		if ev.ScanID != snapshot.Job.ScanID {
			return fail(CodeCrossScopeReference, "evidence is outside this scan")
		}
		if _, ok := hosts[ev.HostID]; !ok {
			return fail(CodeCrossScopeReference, "evidence host is outside this scan")
		}
		if _, ok := attemptIDs[ev.AttemptID]; !ok {
			return fail(CodeUnknownEvidence, "evidence attempt is unknown")
		}
		if attemptIDs[ev.AttemptID].HostID != ev.HostID {
			return fail(CodeCrossScopeReference, "evidence host does not match attempt")
		}
		if _, exists := evidenceByID[ev.EvidenceID]; exists {
			return fail(CodeDuplicateID, "evidence_id is duplicated")
		}
		evidenceByID[ev.EvidenceID] = ev
	}
	if err := validateCoverage(snapshot); err != nil {
		return err
	}
	for _, result := range snapshot.RuleResults {
		if err := result.Validate(); err != nil {
			return err
		}
		if result.ScanID != snapshot.Job.ScanID {
			return fail(CodeCrossScopeReference, "rule result is outside this scan")
		}
		if _, ok := hosts[result.HostID]; !ok {
			return fail(CodeCrossScopeReference, "rule result host is outside this scan")
		}
		if err := validateRuleEvidence(result, evidenceByID); err != nil {
			return err
		}
	}
	for _, finding := range snapshot.Findings {
		if err := ValidateFinding(finding, evidenceByID); err != nil {
			return err
		}
		if finding.ScanID != snapshot.Job.ScanID {
			return fail(CodeCrossScopeReference, "finding is outside this scan")
		}
	}
	if snapshot.Job.AIStatus == AISuccess {
		if snapshot.Assessment == nil {
			return fail(CodeInvalidCanonical, "successful AI status requires an assessment")
		}
	} else if snapshot.Assessment != nil {
		return fail(CodeInvalidCanonical, "assessment is only valid when AI succeeded")
	}
	if snapshot.Assessment != nil {
		allowed := make([]string, 0, len(snapshot.AllowedEvidenceIDs))
		if len(snapshot.AllowedEvidenceIDs) == 0 {
			for id := range evidenceByID {
				allowed = append(allowed, id)
			}
		} else {
			allowed = snapshot.AllowedEvidenceIDs
		}
		if err := ValidateAssessment(*snapshot.Assessment, allowed, evidenceByID, snapshot.Job, snapshot.Findings); err != nil {
			return err
		}
	}
	if snapshot.HumanReview.Status != "pending" && snapshot.HumanReview.Status != "reviewed" {
		return fail(CodeInvalidEnum, "human_review status is invalid")
	}
	if snapshot.Limitations == nil || len(snapshot.Limitations) == 0 {
		return fail(CodeInvalidCanonical, "limitations must describe coverage gaps")
	}
	return nil
}

func validateCoverage(snapshot ScanSnapshot) *Error {
	c := snapshot.CollectionSummary
	if c.TotalModules < 0 || c.Succeeded < 0 || c.Failed < 0 || c.Skipped < 0 {
		return fail(CodeInvalidCanonical, "coverage counts cannot be negative")
	}
	if c.Succeeded+c.Failed+c.Skipped > c.TotalModules {
		return fail(CodeInvalidCanonical, "coverage counts exceed total modules")
	}
	if c.Coverage != nil {
		if *c.Coverage < 0 || *c.Coverage > 1 {
			return fail(CodeInvalidCanonical, "coverage ratio is out of range")
		}
	}
	return nil
}

func validateRuleEvidence(result RuleResult, evidenceByID map[string]Evidence) *Error {
	if result.Outcome == OutcomePass || result.Outcome == OutcomeFail {
		for _, ref := range result.EvidenceRefs {
			ev, ok := evidenceByID[ref]
			if !ok {
				return fail(CodeUnknownEvidence, "rule evidence is unknown")
			}
			if ev.HostID != result.HostID || ev.ScanID != result.ScanID {
				return fail(CodeCrossScopeReference, "rule evidence is out of scope")
			}
			if !ev.SupportsDetection() {
				return fail(CodeEvidenceUnusable, "PASS/FAIL cannot use unusable evidence")
			}
		}
		if result.BaselineRef == nil && result.ReasonCode == "NO_CHANGE" {
			return fail(CodeMissingBaseline, "no-change outcomes require a trusted baseline")
		}
	}
	for _, ref := range result.EvidenceRefs {
		ev, ok := evidenceByID[ref]
		if !ok {
			return fail(CodeUnknownEvidence, "rule evidence is unknown")
		}
		if ev.HostID != result.HostID || ev.ScanID != result.ScanID {
			return fail(CodeCrossScopeReference, "rule evidence is out of scope")
		}
	}
	return nil
}

func ValidateFinding(finding Finding, evidenceIndex map[string]Evidence) error {
	if err := finding.Validate(); err != nil {
		return err
	}
	for _, ref := range finding.EvidenceRefs {
		ev, ok := evidenceIndex[ref]
		if !ok {
			return fail(CodeUnknownEvidence, "finding evidence is unknown")
		}
		if ev.HostID != finding.HostID || ev.ScanID != finding.ScanID {
			return fail(CodeCrossScopeReference, "finding evidence is out of scope")
		}
		if finding.Category == CategoryCollectionFailure {
			if !ev.SupportsCollectionFailure() && !ev.SupportsDetection() {
				return fail(CodeEvidenceUnusable, "collection-failure finding lacks collection evidence")
			}
			continue
		}
		if !ev.SupportsDetection() {
			return fail(CodeEvidenceUnusable, "finding cannot be supported by failed collection")
		}
	}
	return nil
}

func ValidateAssessment(assessment Assessment, allowedEvidence []string, evidenceIndex map[string]Evidence, job ScanJob, findings []Finding) error {
	if err := assessment.Validate(); err != nil {
		return err
	}
	if assessment.ScanID != job.ScanID {
		return fail(CodeCrossScopeReference, "assessment is outside this scan")
	}
	allowed := map[string]struct{}{}
	for _, id := range allowedEvidence {
		allowed[id] = struct{}{}
	}
	check := func(refs []string) *Error {
		for _, ref := range refs {
			if _, ok := allowed[ref]; !ok {
				return fail(CodeUnknownEvidence, "assessment cited evidence outside the allowed set")
			}
			ev, ok := evidenceIndex[ref]
			if !ok {
				return fail(CodeUnknownEvidence, "assessment cited unknown evidence")
			}
			if ev.HostID != assessment.HostID || ev.ScanID != assessment.ScanID {
				return fail(CodeCrossScopeReference, "assessment evidence is out of scope")
			}
		}
		return nil
	}
	if err := check(assessment.EvidenceRefs); err != nil {
		return err
	}
	for _, fact := range append(append([]Fact{}, assessment.Facts...), assessment.Inferences...) {
		if err := check(fact.EvidenceRefs); err != nil {
			return err
		}
	}
	for _, finding := range findings {
		if finding.HostID != assessment.HostID {
			continue
		}
		if severityRank(assessment.RiskLevel) > 0 && severityRank(finding.Severity) != severityRank(assessment.RiskLevel) {
			// Risk level may summarize; it must not claim lower severity than any unreviewed high finding.
			if finding.ReviewStatus == ReviewNew && severityRank(finding.Severity) > severityRank(assessment.RiskLevel) && assessment.RiskLevel != "unknown" {
				return fail(CodeInvalidCanonical, "assessment cannot downgrade finding severity")
			}
		}
	}
	return nil
}

func severityRank(v string) int {
	switch v {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}
