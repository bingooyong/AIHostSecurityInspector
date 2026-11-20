package domain

const (
	SchemaV1     = "1.0"
	ModeReadOnly = "READ_ONLY"

	ProfileQuick            = "quick"
	ProfileStandard         = "standard"
	ProfileDeep             = "deep"
	ProfileIncidentResponse = "incident-response"

	JobCreated         = "CREATED"
	JobValidating      = "VALIDATING"
	JobWaitingApproval = "WAITING_APPROVAL"
	JobQueued          = "QUEUED"
	JobRunning         = "RUNNING"
	JobCollecting      = "COLLECTING"
	JobNormalizing     = "NORMALIZING"
	JobRuleEvaluation  = "RULE_EVALUATION"
	JobAIEnriching     = "AI_ENRICHING"
	JobCompleted       = "COMPLETED"
	JobPartial         = "PARTIAL"
	JobFailed          = "FAILED"
	JobCancelled       = "CANCELLED"
	JobRejected        = "REJECTED"

	AttemptCreated   = "CREATED"
	AttemptRunning   = "RUNNING"
	AttemptCompleted = "COMPLETED"
	AttemptPartial   = "PARTIAL"
	AttemptFailed    = "FAILED"
	AttemptCancelled = "CANCELLED"

	CollectionSuccess       = "success"
	CollectionPartial       = "partial"
	CollectionFailed        = "failed"
	CollectionNotAvailable  = "not_available"
	CollectionNotApplicable = "not_applicable"
	CollectionTimeout       = "timeout"
	CollectionCancelled     = "cancelled"

	ModuleSkipped = "skipped"

	CompletenessComplete    = "complete"
	CompletenessPartial     = "partial"
	CompletenessUnavailable = "unavailable"

	IntegrityVerified    = "verified"
	IntegrityUnverified  = "unverified"
	IntegrityFailed      = "failed"
	IntegrityUnavailable = "unavailable"

	OutcomePass          = "PASS"
	OutcomeFail          = "FAIL"
	OutcomeUnknown       = "UNKNOWN"
	OutcomeNotApplicable = "NOT_APPLICABLE"

	ReviewNew               = "new"
	ReviewNeedsMoreEvidence = "needs_more_evidence"
	ReviewConfirmed         = "confirmed"
	ReviewFalsePositive     = "false_positive"
	ReviewAcceptedRisk      = "accepted_risk"
	ReviewInProgress        = "in_progress"
	ReviewFixed             = "fixed"
	ReviewReopened          = "reopened"

	AIDisabled = "disabled"
	AISkipped  = "skipped"
	AISuccess  = "success"
	AIFailed   = "failed"

	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"

	AssessmentInsufficient = "insufficient_evidence"
	AssessmentNoFindings   = "no_rule_findings"
	AssessmentSuspicious   = "suspicious_activity"
	AssessmentIncident     = "potential_incident"

	CategoryCollectionFailure = "collection_failure"
)

func ValidProfile(name string) bool {
	switch name {
	case ProfileQuick, ProfileStandard, ProfileDeep, ProfileIncidentResponse:
		return true
	}
	return false
}

func ProfileRequiresApproval(name string) bool {
	return name == ProfileDeep || name == ProfileIncidentResponse
}

func ValidCollectionStatus(v string) bool {
	switch v {
	case CollectionSuccess, CollectionPartial, CollectionFailed, CollectionNotAvailable, CollectionNotApplicable, CollectionTimeout, CollectionCancelled:
		return true
	}
	return false
}

func ValidCompleteness(v string) bool {
	switch v {
	case CompletenessComplete, CompletenessPartial, CompletenessUnavailable:
		return true
	}
	return false
}

func ValidIntegrity(v string) bool {
	switch v {
	case IntegrityVerified, IntegrityUnverified, IntegrityFailed, IntegrityUnavailable:
		return true
	}
	return false
}

func ValidOutcome(v string) bool {
	switch v {
	case OutcomePass, OutcomeFail, OutcomeUnknown, OutcomeNotApplicable:
		return true
	}
	return false
}

func ValidReviewStatus(v string) bool {
	switch v {
	case ReviewNew, ReviewNeedsMoreEvidence, ReviewConfirmed, ReviewFalsePositive, ReviewAcceptedRisk, ReviewInProgress, ReviewFixed, ReviewReopened:
		return true
	}
	return false
}

func ValidSeverity(v string) bool {
	switch v {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

func ValidAIStatus(v string) bool {
	switch v {
	case AIDisabled, AISkipped, AISuccess, AIFailed:
		return true
	}
	return false
}

func JobTerminal(status string) bool {
	switch status {
	case JobCompleted, JobPartial, JobFailed, JobCancelled, JobRejected:
		return true
	}
	return false
}

func AttemptTerminal(status string) bool {
	switch status {
	case AttemptCompleted, AttemptPartial, AttemptFailed, AttemptCancelled:
		return true
	}
	return false
}
