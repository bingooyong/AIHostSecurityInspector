package orchestrator

import (
	"context"
	"errors"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

// RunAuthorized advances a job through a legal path around InspectLocal or InspectFixture.
// Cancel, timeout, and collector failure never complete as a successful PASS/COMPLETED scan.
func RunAuthorized(ctx context.Context, jobs *JobStore, job Job, req Request, live bool) (Job, Result, error) {
	created, err := jobs.Create(job)
	if err != nil {
		return Job{}, Result{}, err
	}
	if created.ScanID != job.ScanID {
		return created, Result{}, nil
	}
	created, err = jobs.Advance(created.ScanID, domain.JobValidating)
	if err != nil {
		return created, Result{}, err
	}
	if err := RecheckAuthorization(req); err != nil {
		created, advErr := jobs.Advance(created.ScanID, domain.JobRejected)
		if advErr != nil {
			return created, Result{}, errors.Join(err, advErr)
		}
		return created, Result{ScanID: req.ScanID, HostID: req.HostID, Profile: req.Profile, JobStatus: domain.JobRejected, Limitations: []string{"plan or authorization recheck failed; scan was not started"}}, err
	}
	for _, next := range []string{domain.JobQueued, domain.JobRunning, domain.JobCollecting} {
		created, err = jobs.Advance(created.ScanID, next)
		if err != nil {
			return created, Result{}, err
		}
	}
	var result Result
	if live {
		result, err = InspectLocal(ctx, req)
	} else {
		result, err = InspectFixture(ctx, req)
	}
	if ctx.Err() == context.Canceled {
		created, _ = jobs.Advance(created.ScanID, domain.JobCancelled)
		result.JobStatus = domain.JobCancelled
		return created, result, ctx.Err()
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			created, _ = jobs.Advance(created.ScanID, domain.JobFailed)
			result.JobStatus = domain.JobFailed
			return created, result, ctx.Err()
		}
		created, _ = jobs.Advance(created.ScanID, domain.JobFailed)
		if result.JobStatus == "" || result.JobStatus == domain.JobCreated {
			result.JobStatus = domain.JobFailed
		}
		return created, result, err
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		created, _ = jobs.Advance(created.ScanID, domain.JobFailed)
		return created, result, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "lab or fixture inspect must not mark product scan ready"}
	}
	next := result.JobStatus
	if next == "" || next == domain.JobCreated || next == domain.JobCollecting {
		next = domain.JobPartial
	}
	if next == domain.JobCompleted {
		next = domain.JobPartial
	}
	if next == domain.JobCancelled || next == domain.JobFailed || next == domain.JobPartial {
		if next == domain.JobPartial {
			for _, step := range []string{domain.JobNormalizing, domain.JobRuleEvaluation, domain.JobPartial} {
				created, err = jobs.Advance(created.ScanID, step)
				if err != nil {
					return created, result, err
				}
			}
		} else {
			created, err = jobs.Advance(created.ScanID, next)
			if err != nil {
				return created, result, err
			}
		}
		result.JobStatus = created.Status
		return created, result, nil
	}
	created, _ = jobs.Advance(created.ScanID, domain.JobFailed)
	result.JobStatus = domain.JobFailed
	return created, result, &domain.Error{Code: domain.CodeInvalidStateTransition, Message: "inspect result status is not a legal completion"}
}

func RecheckAuthorization(req Request) error {
	if err := req.Inventory.Validate(); err != nil {
		return err
	}
	if _, err := authorizedHost(req.Inventory, req.HostID, req.Profile); err != nil {
		return err
	}
	if req.SnapshotHash != "" {
		if err := asset.Revalidate(req.SnapshotHash, req.Inventory); err != nil {
			return err
		}
	}
	if req.PolicyHash != "" {
		current, err := policy.CurrentHash(req.Profile)
		if err != nil {
			return err
		}
		if current != req.PolicyHash {
			return errors.New("policy hash drifted")
		}
	}
	return nil
}
