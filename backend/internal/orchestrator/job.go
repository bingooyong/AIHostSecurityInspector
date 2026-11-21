package orchestrator

import (
	"sort"
	"sync"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

var jobTransitions = map[string][]string{
	domain.JobCreated:         {domain.JobValidating, domain.JobRejected, domain.JobCancelled},
	domain.JobValidating:      {domain.JobWaitingApproval, domain.JobQueued, domain.JobRejected},
	domain.JobWaitingApproval: {domain.JobQueued, domain.JobRejected, domain.JobCancelled},
	domain.JobQueued:          {domain.JobRunning, domain.JobCancelled, domain.JobRejected},
	domain.JobRunning:         {domain.JobCollecting, domain.JobFailed, domain.JobCancelled},
	domain.JobCollecting:      {domain.JobNormalizing, domain.JobFailed, domain.JobCancelled, domain.JobPartial},
	domain.JobNormalizing:     {domain.JobRuleEvaluation, domain.JobFailed, domain.JobPartial},
	domain.JobRuleEvaluation:  {domain.JobAIEnriching, domain.JobCompleted, domain.JobPartial, domain.JobFailed},
	domain.JobAIEnriching:     {domain.JobCompleted, domain.JobPartial, domain.JobFailed},
}

type Job struct {
	ScanID         string   `json:"scan_id"`
	HostID         string   `json:"host_id"`
	Profile        string   `json:"profile"`
	Owner          string   `json:"owner"`
	Status         string   `json:"status"`
	History        []string `json:"history"`
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
	CollectorReady bool     `json:"collector_available"`
	ScanReady      bool     `json:"scan_ready"`
	ExecutionReady bool     `json:"execution_ready"`
	Limitations    []string `json:"limitations"`
}

type JobStore struct {
	mu    sync.Mutex
	items map[string]Job
	keys  map[string]string
}

func NewJobStore() *JobStore {
	return &JobStore{items: map[string]Job{}, keys: map[string]string{}}
}

func CanTransition(from, to string) bool {
	for _, next := range jobTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

func (s *JobStore) Create(job Job) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.ScanID == "" || !domain.ValidEntityID(job.ScanID) {
		return Job{}, &domain.Error{Code: domain.CodeInvalidID, Message: "scan_id is invalid"}
	}
	if job.IdempotencyKey != "" {
		if existing, ok := s.keys[job.Owner+"/"+job.IdempotencyKey]; ok {
			return s.items[existing], nil
		}
	}
	if _, ok := s.items[job.ScanID]; ok {
		return Job{}, &domain.Error{Code: domain.CodeDuplicateID, Message: "scan_id already exists"}
	}
	if job.Status == "" {
		job.Status = domain.JobCreated
	}
	if job.Status != domain.JobCreated {
		return Job{}, &domain.Error{Code: domain.CodeInvalidStateTransition, Message: "jobs must start in CREATED"}
	}
	job.CollectorReady = false
	job.ScanReady = false
	job.ExecutionReady = false
	job.History = []string{domain.JobCreated}
	s.items[job.ScanID] = job
	if job.IdempotencyKey != "" {
		s.keys[job.Owner+"/"+job.IdempotencyKey] = job.ScanID
	}
	return job, nil
}

func (s *JobStore) Advance(scanID, next string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.items[scanID]
	if !ok {
		return Job{}, &domain.Error{Code: domain.CodeInvalidID, Message: "scan is unknown"}
	}
	if !CanTransition(job.Status, next) {
		return Job{}, &domain.Error{Code: domain.CodeInvalidStateTransition, Message: "illegal job transition"}
	}
	if next == domain.JobCompleted && (job.CollectorReady || job.ScanReady || job.ExecutionReady) {
		return Job{}, &domain.Error{Code: domain.CodeInvalidStateTransition, Message: "fixture jobs cannot complete as live scans"}
	}
	job.Status = next
	job.History = append(job.History, next)
	s.items[scanID] = job
	return job, nil
}

func (s *JobStore) Get(scanID string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.items[scanID]
	if !ok {
		return Job{}, &domain.Error{Code: domain.CodeInvalidID, Message: "scan is unknown"}
	}
	return job, nil
}

func (s *JobStore) LookupByKey(owner, key string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" {
		return Job{}, false
	}
	id, ok := s.keys[owner+"/"+key]
	if !ok {
		return Job{}, false
	}
	return s.items[id], true
}

func (s *JobStore) List() []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Job, 0, len(s.items))
	for _, job := range s.items {
		out = append(out, job)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScanID < out[j].ScanID })
	return out
}
