package app

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/analyzer"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector/linux"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/orchestrator"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/report"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/storage"
)

type PlanRecord struct {
	PlanID    string       `json:"plan_id"`
	Owner     string       `json:"owner"`
	HostID    string       `json:"host_id"`
	Profile   string       `json:"profile"`
	CreatedAt string       `json:"created_at"`
	Plan      planner.Plan `json:"plan"`
}

type EvidenceMeta struct {
	EvidenceID       string   `json:"evidence_id"`
	ScanID           string   `json:"scan_id"`
	HostID           string   `json:"host_id"`
	Module           string   `json:"module"`
	CollectionStatus string   `json:"collection_status"`
	IntegrityStatus  string   `json:"integrity_status"`
	Completeness     string   `json:"completeness"`
	SHA256           *string  `json:"sha256"`
	Warnings         []string `json:"warnings"`
}

type AuditEvent struct {
	EventID  string `json:"event_id"`
	At       string `json:"at"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	HostID   string `json:"host_id,omitempty"`
	ScanID   string `json:"scan_id,omitempty"`
	PlanID   string `json:"plan_id,omitempty"`
	Decision string `json:"decision"`
}

type Service struct {
	mu          sync.Mutex
	Inventory   asset.Inventory
	Directory   authorization.Directory
	Jobs        *orchestrator.JobStore
	Workflow    *approval.Workflow
	plans       map[string]PlanRecord
	results     map[string]orchestrator.Result
	evidence    map[string]domain.Evidence
	audit       []AuditEvent
	seq         int
	FixtureRoot string
	OutDir      string
	DB          *storage.DB
	Now         func() time.Time
}

func New(inv asset.Inventory, dir authorization.Directory) *Service {
	return &Service{
		Inventory: inv, Directory: dir, Jobs: orchestrator.NewJobStore(), Workflow: approval.NewWorkflow(),
		plans: map[string]PlanRecord{}, results: map[string]orchestrator.Result{}, evidence: map[string]domain.Evidence{},
		audit: []AuditEvent{}, Now: time.Now,
	}
}

func (s *Service) require(caller authorization.Principal, action string) error {
	if _, err := s.Directory.Lookup(caller.ID); err != nil {
		return fail(CodeAuthDenied, "caller is not a local trusted principal")
	}
	if err := caller.Can(action); err != nil {
		return fail(CodeAuthDenied, "principal is not permitted for this action")
	}
	if err := caller.Expand(nil, nil, nil); err != nil {
		return fail(CodeAuthDenied, "self-asserted privileges are rejected")
	}
	return nil
}

func (s *Service) ListAuthorizedHosts(ctx context.Context, caller authorization.Principal, limit, offset int) (Page[PublicHost], error) {
	if err := ctx.Err(); err != nil {
		return Page[PublicHost]{}, err
	}
	if err := s.require(caller, authorization.ActionListHosts); err != nil {
		return Page[PublicHost]{}, err
	}
	return Paginate(PublicHosts(caller.FilterHosts(s.Inventory.Authorized().Hosts)), limit, offset)
}

func (s *Service) ListScanProfiles(_ context.Context, caller authorization.Principal) ([]policy.Profile, error) {
	if err := s.require(caller, authorization.ActionListProfiles); err != nil {
		return nil, err
	}
	names := []string{domain.ProfileQuick, domain.ProfileStandard, domain.ProfileDeep, domain.ProfileIncidentResponse}
	out := make([]policy.Profile, 0, len(names))
	for _, name := range names {
		p, err := policy.Get(name)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Service) PlanHostScan(ctx context.Context, caller authorization.Principal, hostID, profile string) (PlanRecord, error) {
	if err := s.require(caller, authorization.ActionPlan); err != nil {
		return PlanRecord{}, err
	}
	if _, _, err := authorization.SelectFor(ctx, s.Inventory, caller, hostID, "", profile); err != nil {
		return PlanRecord{}, fail(CodeHostNotAuthorized, "host or profile is not authorized for this principal")
	}
	plan, err := planner.Build(ctx, s.Inventory, planner.Request{HostID: hostID, Profile: profile, DryRun: true})
	if err != nil {
		return PlanRecord{}, err
	}
	s.mu.Lock()
	s.seq++
	rec := PlanRecord{
		PlanID: fmt.Sprintf("plan-%d", s.seq), Owner: caller.ID, HostID: hostID, Profile: profile,
		CreatedAt: s.Now().UTC().Format(domain.TimeLayout), Plan: *plan,
	}
	s.plans[rec.PlanID] = rec
	s.mu.Unlock()
	s.recordAudit(caller.ID, "plan_host_scan", hostID, "", rec.PlanID, "allow")
	return rec, nil
}

func (s *Service) RequestScanApproval(_ context.Context, caller authorization.Principal, planID, reason string) (approval.Request, error) {
	if err := s.require(caller, authorization.ActionRequestApproval); err != nil {
		return approval.Request{}, err
	}
	s.mu.Lock()
	plan, ok := s.plans[planID]
	s.mu.Unlock()
	if !ok || plan.Owner != caller.ID {
		return approval.Request{}, fail(CodeNotFound, "plan is unknown to this principal")
	}
	if !plan.Plan.ApprovalRequired {
		return approval.Request{}, fail(CodeSchema, "this profile does not request approval; planning is not an execution grant")
	}
	s.mu.Lock()
	s.seq++
	requestID := fmt.Sprintf("request-%d", s.seq)
	s.mu.Unlock()
	rec, err := s.Workflow.Request(requestID, planID, "plan:"+planID, caller.ID, reason)
	if err != nil {
		return rec, err
	}
	s.recordAudit(caller.ID, "request_scan_approval", plan.HostID, "", planID, "allow")
	return rec, nil
}

func (s *Service) RunHostScan(ctx context.Context, caller authorization.Principal, planID, approvalID, idempotency, hostID, profile string) (orchestrator.Job, orchestrator.Result, error) {
	if err := s.require(caller, authorization.ActionRunFixture); err != nil {
		return orchestrator.Job{}, orchestrator.Result{}, err
	}
	if s.FixtureRoot == "" || s.OutDir == "" {
		return orchestrator.Job{}, orchestrator.Result{}, fail(CodeToolNotInstalled, "fixture root is required; live host scan is unavailable")
	}
	if err := linux.ValidateInspectRoot(s.FixtureRoot); err != nil {
		return orchestrator.Job{}, orchestrator.Result{}, fail(CodeSchema, "inspect root is not an allowed synthetic fixture")
	}
	if hostID == "" || profile == "" {
		s.mu.Lock()
		plan, ok := s.plans[planID]
		s.mu.Unlock()
		if !ok || plan.Owner != caller.ID {
			return orchestrator.Job{}, orchestrator.Result{}, fail(CodeNotFound, "plan is unknown to this principal")
		}
		hostID, profile = plan.HostID, plan.Profile
	}
	if _, _, err := authorization.SelectFor(ctx, s.Inventory, caller, hostID, "", profile); err != nil {
		return orchestrator.Job{}, orchestrator.Result{}, fail(CodeHostNotAuthorized, "host is not authorized for this principal")
	}
	if domain.ProfileRequiresApproval(profile) {
		if approvalID == "" {
			return orchestrator.Job{}, orchestrator.Result{}, fail(CodeApprovalRequired, "deep and incident-response require a consumed approval")
		}
		return orchestrator.Job{}, orchestrator.Result{}, fail(CodeToolNotInstalled, "deep fixture execution is not enabled without a live collector")
	}
	if idempotency != "" {
		if existing, ok := s.Jobs.LookupByKey(caller.ID, idempotency); ok {
			return s.storedScan(existing)
		}
	}
	s.mu.Lock()
	s.seq++
	scanID := fmt.Sprintf("scan-local-%d", s.seq)
	s.mu.Unlock()
	job, err := s.Jobs.Create(orchestrator.Job{ScanID: scanID, HostID: hostID, Profile: profile, Owner: caller.ID, IdempotencyKey: idempotency})
	if err != nil {
		return orchestrator.Job{}, orchestrator.Result{}, err
	}
	if job.ScanID != scanID {
		return s.storedScan(job)
	}
	for _, next := range []string{domain.JobValidating, domain.JobQueued, domain.JobRunning, domain.JobCollecting} {
		if job, err = s.Jobs.Advance(job.ScanID, next); err != nil {
			return job, orchestrator.Result{}, err
		}
	}
	result, err := orchestrator.InspectFixture(ctx, orchestrator.Request{
		Root: s.FixtureRoot, Inventory: s.Inventory, HostID: hostID, Profile: profile, OutDir: s.OutDir, ScanID: job.ScanID, Now: s.Now,
	})
	if err != nil {
		_, _ = s.Jobs.Advance(job.ScanID, domain.JobFailed)
		return job, result, err
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		_, _ = s.Jobs.Advance(job.ScanID, domain.JobFailed)
		return job, result, fail(CodeSchema, "fixture inspect must not mark scan ready")
	}
	for _, next := range []string{domain.JobNormalizing, domain.JobRuleEvaluation, domain.JobPartial} {
		if job, err = s.Jobs.Advance(job.ScanID, next); err != nil {
			return job, result, err
		}
	}
	s.RememberInspect(result)
	s.rememberEvidence(job.ScanID, result.Evidence)
	_ = approvalID
	s.recordAudit(caller.ID, "run_host_scan", hostID, job.ScanID, planID, "allow")
	return job, result, nil
}

func (s *Service) rememberEvidence(scanID string, items []domain.Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range items {
		s.evidence[item.EvidenceID] = item
	}
	if result, ok := s.results[scanID]; ok {
		s.results[scanID] = result
	}
}

func (s *Service) storedScan(job orchestrator.Job) (orchestrator.Job, orchestrator.Result, error) {
	s.mu.Lock()
	result := s.results[job.ScanID]
	s.mu.Unlock()
	return job, result, nil
}

func (s *Service) ListScans(_ context.Context, caller authorization.Principal, limit, offset int) (Page[orchestrator.Job], error) {
	if err := s.require(caller, authorization.ActionReadScan); err != nil {
		return Page[orchestrator.Job]{}, err
	}
	visible := make([]orchestrator.Job, 0)
	for _, job := range s.Jobs.List() {
		if err := s.visibleHost(caller, job.HostID); err != nil {
			continue
		}
		visible = append(visible, job)
	}
	return Paginate(visible, limit, offset)
}

func (s *Service) GetScanStatus(_ context.Context, caller authorization.Principal, scanID string) (orchestrator.Job, error) {
	if err := s.require(caller, authorization.ActionReadScan); err != nil {
		return orchestrator.Job{}, err
	}
	job, err := s.Jobs.Get(scanID)
	if err != nil {
		return orchestrator.Job{}, fail(CodeNotFound, "scan is unknown")
	}
	if err := s.visibleHost(caller, job.HostID); err != nil {
		return orchestrator.Job{}, err
	}
	return job, nil
}

func (s *Service) findingsFor(caller authorization.Principal, scanID string) ([]domain.Finding, []domain.RuleResult, error) {
	if err := s.require(caller, authorization.ActionReadScan); err != nil {
		return nil, nil, err
	}
	job, err := s.Jobs.Get(scanID)
	if err != nil {
		return nil, nil, fail(CodeNotFound, "scan is unknown")
	}
	if err := s.visibleHost(caller, job.HostID); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, ok := s.results[scanID]
	if !ok {
		return nil, nil, fail(CodeNotFound, "scan results are unknown")
	}
	return result.Findings, result.RuleResults, nil
}

func (s *Service) ListFindings(_ context.Context, caller authorization.Principal, scanID string, limit, offset int) (Page[domain.Finding], []domain.RuleResult, error) {
	findings, rules, err := s.findingsFor(caller, scanID)
	if err != nil {
		return Page[domain.Finding]{}, nil, err
	}
	page, err := Paginate(findings, limit, offset)
	if err != nil {
		return Page[domain.Finding]{}, nil, err
	}
	return page, rules, nil
}

func (s *Service) GetEvidenceMetadata(_ context.Context, caller authorization.Principal, evidenceID string) (EvidenceMeta, error) {
	if err := s.require(caller, authorization.ActionReadScan); err != nil {
		return EvidenceMeta{}, err
	}
	s.mu.Lock()
	item, ok := s.evidence[evidenceID]
	s.mu.Unlock()
	if !ok {
		return EvidenceMeta{}, fail(CodeNotFound, "evidence is unknown")
	}
	if err := s.visibleHost(caller, item.HostID); err != nil {
		return EvidenceMeta{}, err
	}
	return metaFrom(item), nil
}

func (s *Service) ListEvidence(_ context.Context, caller authorization.Principal, scanID string, limit, offset int) (Page[EvidenceMeta], error) {
	if err := s.require(caller, authorization.ActionReadScan); err != nil {
		return Page[EvidenceMeta]{}, err
	}
	job, err := s.Jobs.Get(scanID)
	if err != nil {
		return Page[EvidenceMeta]{}, fail(CodeNotFound, "scan is unknown")
	}
	if err := s.visibleHost(caller, job.HostID); err != nil {
		return Page[EvidenceMeta]{}, err
	}
	s.mu.Lock()
	items := make([]EvidenceMeta, 0)
	for _, item := range s.evidence {
		if item.ScanID == scanID {
			items = append(items, metaFrom(item))
		}
	}
	s.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].EvidenceID < items[j].EvidenceID })
	return Paginate(items, limit, offset)
}

func (s *Service) ListApprovals(_ context.Context, caller authorization.Principal, limit, offset int) (Page[approval.Request], error) {
	if err := s.require(caller, authorization.ActionReadScan); err != nil {
		return Page[approval.Request]{}, err
	}
	visible := make([]approval.Request, 0)
	for _, rec := range s.Workflow.List() {
		s.mu.Lock()
		plan, ok := s.plans[rec.PlanID]
		s.mu.Unlock()
		if !ok {
			continue
		}
		if err := s.visibleHost(caller, plan.HostID); err != nil {
			continue
		}
		visible = append(visible, rec)
	}
	return Paginate(visible, limit, offset)
}

func (s *Service) ListAudit(_ context.Context, caller authorization.Principal, limit, offset int) (Page[AuditEvent], error) {
	if err := s.require(caller, authorization.ActionReadAudit); err != nil {
		return Page[AuditEvent]{}, err
	}
	s.mu.Lock()
	events := append([]AuditEvent{}, s.audit...)
	s.mu.Unlock()
	visible := make([]AuditEvent, 0, len(events))
	for _, event := range events {
		if event.HostID != "" {
			if err := s.visibleHost(caller, event.HostID); err != nil {
				continue
			}
		}
		visible = append(visible, event)
	}
	return Paginate(visible, limit, offset)
}

func (s *Service) UseDB(ctx context.Context, db *storage.DB) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DB = db
	if db == nil {
		return nil
	}
	rows, err := db.ListAudit(ctx)
	if err != nil {
		return err
	}
	s.audit = s.audit[:0]
	for _, row := range rows {
		s.audit = append(s.audit, AuditEvent{
			EventID: row.EventID, At: row.At, Actor: row.Actor, Action: row.Action,
			HostID: row.HostID, ScanID: row.ScanID, PlanID: row.PlanID, Decision: row.Decision,
		})
	}
	return nil
}

func (s *Service) recordAudit(actor, action, hostID, scanID, planID, decision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	event := AuditEvent{
		EventID: fmt.Sprintf("audit-%d", s.seq), At: s.Now().UTC().Format(domain.TimeLayout),
		Actor: actor, Action: action, HostID: hostID, ScanID: scanID, PlanID: planID, Decision: decision,
	}
	s.audit = append(s.audit, event)
	if s.DB != nil {
		_ = s.DB.AppendAudit(context.Background(), storage.AuditRow{
			EventID: event.EventID, At: event.At, Actor: event.Actor, Action: event.Action,
			HostID: event.HostID, ScanID: event.ScanID, PlanID: event.PlanID, Decision: event.Decision,
		})
	}
}

func metaFrom(item domain.Evidence) EvidenceMeta {
	return EvidenceMeta{
		EvidenceID: item.EvidenceID, ScanID: item.ScanID, HostID: item.HostID, Module: item.Module,
		CollectionStatus: item.CollectionStatus, IntegrityStatus: item.IntegrityStatus, Completeness: item.Completeness,
		SHA256: item.SHA256, Warnings: item.Warnings,
	}
}

func (s *Service) AnalyzeScanFindings(ctx context.Context, caller authorization.Principal, scanID string) (analyzer.Result, error) {
	if err := s.require(caller, authorization.ActionAnalyze); err != nil {
		return analyzer.Result{}, err
	}
	findings, _, err := s.findingsFor(caller, scanID)
	if err != nil {
		return analyzer.Result{}, err
	}
	view := analyzer.Minimize(findings, nil)
	return analyzer.Provider{Enabled: false}.Enrich(ctx, view)
}

func (s *Service) GenerateScanReport(_ context.Context, caller authorization.Principal, scanID, format string) (report.Document, string, error) {
	if err := s.require(caller, authorization.ActionReport); err != nil {
		return report.Document{}, "", err
	}
	job, err := s.Jobs.Get(scanID)
	if err != nil {
		return report.Document{}, "", fail(CodeNotFound, "scan is unknown")
	}
	if err := s.visibleHost(caller, job.HostID); err != nil {
		return report.Document{}, "", err
	}
	s.mu.Lock()
	result, ok := s.results[scanID]
	s.mu.Unlock()
	if !ok {
		return report.Document{}, "", fail(CodeNotFound, "scan results are unknown")
	}
	doc := report.Build(result.ScanID, result.HostID, result.Profile, nil, result.RuleResults, result.Findings, result.Integrity, result.Limitations)
	switch format {
	case "", "json":
		return doc, "", nil
	case "md":
		return doc, report.Markdown(doc), nil
	default:
		return report.Document{}, "", fail(CodeSchema, "unsupported report format")
	}
}

func (s *Service) RememberInspect(result orchestrator.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[result.ScanID] = result
}

func (s *Service) visibleHost(caller authorization.Principal, hostID string) error {
	for _, host := range s.Inventory.Hosts {
		if host.ID == hostID {
			if err := caller.AllowsHost(host); err != nil {
				return fail(CodeHostNotAuthorized, "scan is not visible to this principal")
			}
			return nil
		}
	}
	return fail(CodeHostNotAuthorized, "scan is not visible to this principal")
}
