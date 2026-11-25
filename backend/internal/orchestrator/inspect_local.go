package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/adapter"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/baseline"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector/linux"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/evidence"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/intel"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/report"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/rules"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/transport/ssh"
)

// InspectLocal collects from this machine's root filesystem, or over a
// loopback-only SSH transport with a strict known_hosts policy.
// Product flags stay false: this is a lab path, not enterprise scan readiness.
func InspectLocal(ctx context.Context, req Request) (Result, error) {
	out := Result{
		ScanID: req.ScanID, HostID: req.HostID, Profile: req.Profile,
		CollectorAvailable: false, ScanReady: false, ExecutionReady: false,
		Modules: []collector.Result{}, RuleResults: []domain.RuleResult{}, Findings: []domain.Finding{},
		ToolReports: []adapter.Report{}, Evidence: []domain.Evidence{}, JobStatus: domain.JobCreated, AIStatus: domain.AIDisabled,
		Limitations: []string{
			"lab collection on an authorized loopback host only",
			"not enterprise host scanning",
			"doctor collector_available and scan_ready remain false",
			"local identity or local CA is not a platform IdP or production mTLS",
		},
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if req.Now == nil {
		req.Now = time.Now
	}
	if req.ScanID == "" {
		req.ScanID = "scan-lab-001"
		out.ScanID = req.ScanID
	}
	if req.AttemptID == "" {
		req.AttemptID = "attempt-lab-001"
	}
	if req.Root == "" {
		req.Root = "/"
	}
	if err := linux.ValidateLiveRoot(req.Root); err != nil {
		return out, err
	}
	host, err := authorizedHost(req.Inventory, req.HostID, req.Profile)
	if err != nil {
		return out, err
	}
	if err := asset.LoopbackOnly(host); err != nil {
		return out, err
	}
	prof, err := policy.Get(req.Profile)
	if err != nil {
		return out, err
	}
	if prof.ApprovalRequired {
		return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "deep and incident-response still require a verified approval and are refused here"}
	}
	if req.SSH != nil {
		if err := req.SSH.Validate(); err != nil {
			return out, err
		}
		out.Limitations = append(out.Limitations, "SSH transport used with strict known_hosts on loopback")
	} else {
		out.Limitations = append(out.Limitations, "SSH transport was not used; collection was local filesystem")
	}
	store, err := evidence.Open(ctx, req.OutDir, req.Now)
	if err != nil {
		return out, err
	}
	defer func() { _ = store.Close() }()
	timeout := time.Duration(prof.Limits.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	moduleTimeout := timeout / time.Duration(len(prof.Modules)+1)
	for i, module := range prof.Modules {
		if err := beforeModule(ctx, req.Pressure, prof.Limits.StopOnResourcePressure); err != nil {
			if errors.Is(err, ErrResourcePressure) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				out.Modules = append(out.Modules, skippedModules(prof.Modules[i:], req, err)...)
				break
			}
			out.JobStatus = domain.JobFailed
			return failOpen(out, err)
		}
		creq := collector.Request{
			ScanID: req.ScanID, AttemptID: req.AttemptID, HostID: req.HostID,
			ModuleID: module, Profile: req.Profile, PolicyVersion: policy.PolicyVersion,
			Limits: collector.Limits{Timeout: moduleTimeout, MaxRecords: 4096, MaxBytes: 1 << 20},
		}
		var result collector.Result
		if req.SSH != nil {
			result = collectOverSSH(ctx, *req.SSH, req.Now, creq)
		} else {
			result = linux.CollectModule(ctx, req.Root, true, req.Now, creq)
		}
		out.Modules = append(out.Modules, result)
		if err := putResult(ctx, store, req, result); err != nil {
			out.JobStatus = domain.JobFailed
			return failOpen(out, err)
		}
	}
	if _, err := store.BuildManifest(ctx, req.ScanID, policy.PolicyVersion); err != nil {
		return failOpen(out, err)
	}
	reportVerify, err := store.Verify(ctx, req.ScanID)
	if err != nil {
		return failOpen(out, err)
	}
	out.Integrity = reportVerify
	items, err := store.List(ctx, req.ScanID)
	if err != nil {
		return failOpen(out, err)
	}
	bundle, err := rules.Load(rules.DefaultBundle)
	if err != nil {
		return failOpen(out, err)
	}
	base := baseline.Candidate(req.HostID, req.ScanID)
	results, findings, err := rules.Evaluate(ctx, req.ScanID, req.HostID, req.Profile, items, base, bundle)
	if err != nil {
		return failOpen(out, err)
	}
	results = rejectPassOnFailedCollection(results, out.Modules)
	out.RuleResults = results
	out.Findings = findings
	out.Evidence = items
	out.JobStatus, out.JobStatusReason = labJobStatus(out.Modules)
	exec := tools.Executor{}
	for _, tool := range prof.Tools {
		rep, toolErr := runNamed(ctx, exec, tool, req.HostID, req.ScanID)
		if toolErr != nil {
			return failOpen(out, toolErr)
		}
		out.ToolReports = append(out.ToolReports, rep)
	}
	out.Intel = intel.Correlate(items, nil)
	doc := report.BuildFromInput(reportInput(out, bundle))
	path, err := report.Write(req.OutDir, doc)
	if err != nil {
		return failOpen(out, err)
	}
	out.ReportPath = path
	if out.CollectorAvailable || out.ScanReady || out.ExecutionReady {
		return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "lab inspect must not mark product scan ready"}
	}
	return out, nil
}

func collectOverSSH(ctx context.Context, cfg ssh.DialConfig, now func() time.Time, req collector.Request) collector.Result {
	started := time.Now().UTC()
	if now != nil {
		started = now().UTC()
	}
	failed := collector.Result{
		ModuleID: req.ModuleID, Version: collector.Version, StartedAt: started.Format(domain.TimeLayout),
		Status: domain.CollectionFailed, Completeness: domain.CompletenessUnavailable,
		Records: []map[string]any{}, RawRefs: []string{}, Warnings: []string{"ssh_collect_failed"},
		ErrorCode: "SSH_COLLECT_FAILED",
	}
	args, err := ssh.BuildCollectorArgs(req.ModuleID, req.ScanID, req.AttemptID, req.HostID, req.Profile, req.PolicyVersion)
	if err != nil {
		return failed
	}
	cfg.Policy.AllowedBinary = ssh.CollectorBinary
	cfg.Policy.AllowedArgs = args
	raw, err := ssh.Run(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			failed.Status = statusForContext(ctx.Err())
			failed.ErrorCode = "MODULE_" + failed.Status
			failed.Warnings = []string{"ssh_collect_cancelled_or_timed_out"}
			return failed
		}
		failed.Warnings = append(failed.Warnings, "ssh_transport_error")
		return failed
	}
	var result collector.Result
	if err := json.Unmarshal(raw, &result); err != nil {
		failed.Warnings = append(failed.Warnings, "ssh_collect_output_invalid")
		return failed
	}
	if result.ModuleID == "" {
		result.ModuleID = req.ModuleID
	}
	return result
}

func statusForContext(err error) string {
	if err == nil {
		return domain.CollectionFailed
	}
	if err == context.Canceled {
		return domain.CollectionCancelled
	}
	if err == context.DeadlineExceeded {
		return domain.CollectionTimeout
	}
	return domain.CollectionFailed
}

func countModuleStatuses(modules []collector.Result) (success, partial, failed, timeout, cancelled int) {
	for _, module := range modules {
		switch module.Status {
		case domain.CollectionCancelled:
			cancelled++
		case domain.CollectionTimeout:
			timeout++
		case domain.CollectionFailed:
			failed++
		case domain.CollectionPartial, domain.CollectionNotAvailable, domain.CollectionNotApplicable:
			partial++
		case domain.CollectionSuccess:
			success++
		default:
			failed++
		}
	}
	return success, partial, failed, timeout, cancelled
}

// labJobStatus never returns COMPLETED. A fully successful lab collection is
// still PARTIAL because this path is not a production completed scan.
func labJobStatus(modules []collector.Result) (string, string) {
	if len(modules) == 0 {
		return domain.JobFailed, "no modules were collected"
	}
	success, partial, failed, timeout, cancelled := countModuleStatuses(modules)
	counts := fmt.Sprintf("success=%d partial=%d failed=%d timeout=%d cancelled=%d", success, partial, failed, timeout, cancelled)
	if cancelled > 0 {
		return domain.JobCancelled, "lab collection cancelled (" + counts + "); not a production completed scan"
	}
	if failed == len(modules) {
		return domain.JobFailed, "all lab modules failed (" + counts + ")"
	}
	if timeout == len(modules) {
		return domain.JobFailed, "all lab modules timed out (" + counts + ")"
	}
	if failed > 0 || timeout > 0 || partial > 0 {
		return domain.JobPartial, "lab collection incomplete (" + counts + "); not a production completed scan"
	}
	return domain.JobPartial, "all lab modules collected successfully; status remains PARTIAL because this is not a production completed scan"
}

func rejectPassOnFailedCollection(results []domain.RuleResult, modules []collector.Result) []domain.RuleResult {
	hardFail := false
	for _, module := range modules {
		if module.Status == domain.CollectionFailed || module.Status == domain.CollectionTimeout || module.Status == domain.CollectionCancelled {
			hardFail = true
			break
		}
	}
	if !hardFail {
		return results
	}
	out := make([]domain.RuleResult, len(results))
	copy(out, results)
	for i, result := range out {
		if result.Outcome != domain.OutcomePass {
			continue
		}
		out[i].Outcome = domain.OutcomeUnknown
		out[i].ReasonCode = "collection_failed"
	}
	return out
}

func failOpen(out Result, err error) (Result, error) {
	if out.JobStatus == domain.JobCreated || out.JobStatus == "" {
		if err == context.Canceled {
			out.JobStatus = domain.JobCancelled
		} else {
			out.JobStatus = domain.JobFailed
		}
	}
	return out, err
}
