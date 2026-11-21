package domain

var jobTransitions = map[string][]string{
	JobCreated:         {JobValidating, JobCancelled},
	JobValidating:      {JobWaitingApproval, JobQueued, JobRejected, JobCancelled, JobFailed},
	JobWaitingApproval: {JobQueued, JobRejected, JobCancelled, JobFailed},
	JobQueued:          {JobRunning, JobCancelled, JobFailed},
	JobRunning:         {JobCollecting, JobCancelled, JobFailed, JobPartial},
	JobCollecting:      {JobNormalizing, JobCancelled, JobFailed, JobPartial},
	JobNormalizing:     {JobRuleEvaluation, JobCancelled, JobFailed, JobPartial},
	JobRuleEvaluation:  {JobAIEnriching, JobCompleted, JobPartial, JobFailed, JobCancelled},
	JobAIEnriching:     {JobCompleted, JobPartial, JobCancelled},
}

var attemptTransitions = map[string][]string{
	AttemptCreated: {AttemptRunning, AttemptCancelled},
	AttemptRunning: {AttemptCompleted, AttemptPartial, AttemptFailed, AttemptCancelled},
}

type ScanJob struct {
	ScanID             string   `json:"scan_id"`
	RequesterPrincipal string   `json:"requester_principal"`
	HostIDs            []string `json:"host_ids"`
	Profile            string   `json:"profile"`
	PlanHash           string   `json:"plan_hash"`
	PolicyVersion      string   `json:"policy_version"`
	RuleBundleVersion  string   `json:"rule_bundle_version"`
	CollectorVersion   string   `json:"collector_version"`
	Status             string   `json:"status"`
	CreatedAt          string   `json:"created_at"`
	StartedAt          string   `json:"started_at,omitempty"`
	CompletedAt        string   `json:"completed_at,omitempty"`
	FailureReason      string   `json:"failure_reason,omitempty"`
	AIStatus           string   `json:"ai_status"`
}

type ScanAttempt struct {
	AttemptID string            `json:"attempt_id"`
	ScanID    string            `json:"scan_id"`
	HostID    string            `json:"host_id"`
	Status    string            `json:"status"`
	RetryOf   string            `json:"retry_of,omitempty"`
	StartedAt string            `json:"started_at"`
	EndedAt   string            `json:"ended_at,omitempty"`
	Transport string            `json:"transport"`
	Modules   map[string]string `json:"modules"`
}

func CanTransition(from, to string) bool {
	allowed, ok := jobTransitions[from]
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if candidate == to {
			return true
		}
	}
	return false
}

func CanTransitionAttempt(from, to string) bool {
	allowed, ok := attemptTransitions[from]
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if candidate == to {
			return true
		}
	}
	return false
}

func (j ScanJob) Validate() error {
	if !ValidEntityID(j.ScanID) {
		return fail(CodeInvalidID, "scan_id is invalid")
	}
	if !ValidEntityID(j.RequesterPrincipal) {
		return fail(CodeInvalidID, "requester principal is invalid")
	}
	if len(j.HostIDs) == 0 || !uniqueNonEmpty(j.HostIDs, ValidHostID) {
		return fail(CodeInvalidID, "host_ids are invalid")
	}
	if !ValidProfile(j.Profile) {
		return fail(CodeInvalidEnum, "profile is not supported")
	}
	if !ValidSHA256(j.PlanHash) {
		return fail(CodeInvalidCanonical, "plan_hash is not SHA-256")
	}
	if !ValidVersion(j.PolicyVersion) || !ValidVersion(j.RuleBundleVersion) || !ValidVersion(j.CollectorVersion) {
		return fail(CodeInvalidID, "version field is invalid")
	}
	if _, ok := jobTransitions[j.Status]; !ok && !JobTerminal(j.Status) {
		return fail(CodeInvalidEnum, "scan job status is unknown")
	}
	if !ValidAIStatus(j.AIStatus) {
		return fail(CodeInvalidEnum, "ai_status is unknown")
	}
	if _, err := ParseUTC(j.CreatedAt); err != nil {
		return err
	}
	if j.StartedAt != "" {
		if err := requireOrder(j.CreatedAt, j.StartedAt, true); err != nil {
			return err
		}
	}
	if JobTerminal(j.Status) {
		if j.CompletedAt == "" {
			return fail(CodeInvalidTimestamp, "terminal jobs require completed_at")
		}
		anchor := j.StartedAt
		if anchor == "" {
			anchor = j.CreatedAt
		}
		if err := requireOrder(anchor, j.CompletedAt, true); err != nil {
			return err
		}
	} else if j.CompletedAt != "" {
		return fail(CodeInvalidTimestamp, "non-terminal jobs cannot set completed_at")
	}
	return nil
}

func (j ScanJob) Transition(to string) (ScanJob, error) {
	if err := j.Validate(); err != nil {
		return ScanJob{}, err
	}
	if JobTerminal(j.Status) {
		return ScanJob{}, fail(CodeInvalidStateTransition, "terminal job cannot change status")
	}
	if !CanTransition(j.Status, to) {
		return ScanJob{}, fail(CodeInvalidStateTransition, "scan job transition is not allowed")
	}
	next := j
	next.Status = to
	return next, nil
}

func (a ScanAttempt) Validate() error {
	if !ValidEntityID(a.AttemptID) || !ValidEntityID(a.ScanID) || !ValidHostID(a.HostID) {
		return fail(CodeInvalidID, "attempt identity is invalid")
	}
	if a.RetryOf != "" && !ValidEntityID(a.RetryOf) {
		return fail(CodeInvalidID, "retry_of is invalid")
	}
	if a.RetryOf == a.AttemptID {
		return fail(CodeInvalidID, "attempt cannot retry itself")
	}
	if _, ok := attemptTransitions[a.Status]; !ok && !AttemptTerminal(a.Status) {
		return fail(CodeInvalidEnum, "attempt status is unknown")
	}
	if a.Transport != "ssh" && a.Transport != "local" {
		return fail(CodeInvalidEnum, "transport is not supported")
	}
	if err := requireOrder(a.StartedAt, a.EndedAt, AttemptTerminal(a.Status)); err != nil {
		return err
	}
	if AttemptTerminal(a.Status) && a.EndedAt == "" {
		return fail(CodeInvalidTimestamp, "terminal attempts require ended_at")
	}
	if !AttemptTerminal(a.Status) && a.EndedAt != "" {
		return fail(CodeInvalidTimestamp, "active attempts cannot set ended_at")
	}
	for module, status := range a.Modules {
		if !ValidEntityID(module) {
			return fail(CodeInvalidID, "module name is invalid")
		}
		if !ValidCollectionStatus(status) && status != ModuleSkipped {
			return fail(CodeInvalidEnum, "module status is unknown")
		}
	}
	return nil
}

func (a ScanAttempt) Transition(to string) (ScanAttempt, error) {
	if err := a.Validate(); err != nil {
		return ScanAttempt{}, err
	}
	if AttemptTerminal(a.Status) {
		return ScanAttempt{}, fail(CodeInvalidStateTransition, "terminal attempt cannot change status")
	}
	if !CanTransitionAttempt(a.Status, to) {
		return ScanAttempt{}, fail(CodeInvalidStateTransition, "attempt transition is not allowed")
	}
	next := a
	next.Status = to
	return next, nil
}
