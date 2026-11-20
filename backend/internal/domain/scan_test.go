package domain

import "testing"

func TestScanJobTransitions(t *testing.T) {
	job := validJob()
	job.Status = JobCreated
	job.CompletedAt = ""
	job.StartedAt = ""
	next, err := job.Transition(JobValidating)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.Transition(JobCompleted); err == nil {
		t.Fatal("skipped required states")
	}
	terminal := validJob()
	if _, err := terminal.Transition(JobRunning); err == nil {
		t.Fatal("terminal job accepted a write")
	}
}

func TestAttemptRejectsSelfRetryAndInvertedTime(t *testing.T) {
	a := validAttempt()
	a.RetryOf = a.AttemptID
	if err := a.Validate(); err == nil {
		t.Fatal("self retry accepted")
	}
	a = validAttempt()
	a.EndedAt = "2026-11-19T00:00:00Z"
	if err := a.Validate(); err == nil {
		t.Fatal("inverted timestamps accepted")
	}
	a = validAttempt()
	a.Status = AttemptRunning
	a.EndedAt = ""
	if _, err := a.Transition(AttemptCompleted); err != nil {
		t.Fatal(err)
	}
	done := validAttempt()
	if _, err := done.Transition(AttemptRunning); err == nil {
		t.Fatal("terminal attempt mutated")
	}
}

func TestOfflinePlanCannotClaimExecution(t *testing.T) {
	// ValidateOfflinePlan is covered with planner types in convert_test.go.
	if CanTransition(JobCompleted, JobRunning) {
		t.Fatal("completed jobs must not restart in-place")
	}
	if !CanTransition(JobRuleEvaluation, JobAIEnriching) || !CanTransition(JobAIEnriching, JobCompleted) {
		t.Fatal("AI enriching path missing")
	}
}
