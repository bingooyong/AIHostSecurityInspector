package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
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

type Request struct {
	Root         string
	Live         bool
	Inventory    asset.Inventory
	HostID       string
	Profile      string
	OutDir       string
	ScanID       string
	AttemptID    string
	Now          func() time.Time
	SSH          *ssh.DialConfig
	Pressure     PressureSource
	SnapshotHash string
	PolicyHash   string
}

type Result struct {
	ScanID             string                      `json:"scan_id"`
	HostID             string                      `json:"host_id"`
	Profile            string                      `json:"profile"`
	CollectorAvailable bool                        `json:"collector_available"`
	ScanReady          bool                        `json:"scan_ready"`
	ExecutionReady     bool                        `json:"execution_ready"`
	Integrity          evidence.VerificationReport `json:"integrity"`
	Modules            []collector.Result          `json:"modules"`
	RuleResults        []domain.RuleResult         `json:"rule_results"`
	Findings           []domain.Finding            `json:"findings"`
	ToolReports        []adapter.Report            `json:"tool_reports"`
	Intel              intel.Report                `json:"intel"`
	AIStatus           string                      `json:"ai_status"`
	ReportPath         string                      `json:"report_path"`
	Evidence           []domain.Evidence           `json:"evidence"`
	JobStatus          string                      `json:"job_status"`
	JobStatusReason    string                      `json:"job_status_reason,omitempty"`
	Limitations        []string                    `json:"limitations"`
}

func InspectFixture(ctx context.Context, req Request) (Result, error) {
	out := Result{
		ScanID: req.ScanID, HostID: req.HostID, Profile: req.Profile,
		CollectorAvailable: false, ScanReady: false, ExecutionReady: false,
		Modules: []collector.Result{}, RuleResults: []domain.RuleResult{}, Findings: []domain.Finding{},
		ToolReports: []adapter.Report{}, Evidence: []domain.Evidence{}, JobStatus: domain.JobCreated, AIStatus: domain.AIDisabled,
		Limitations: []string{
			"fixture inspect is not enterprise host scanning",
			"doctor collector_available and scan_ready remain false",
			"SSH transport was not used",
			"AI is disabled",
		},
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if req.Now == nil {
		req.Now = time.Now
	}
	if req.ScanID == "" {
		req.ScanID = "scan-fixture-001"
		out.ScanID = req.ScanID
	}
	if req.AttemptID == "" {
		req.AttemptID = "attempt-fixture-001"
	}
	if err := linux.ValidateInspectRoot(req.Root); err != nil {
		return out, err
	}
	host, err := authorizedHost(req.Inventory, req.HostID, req.Profile)
	if err != nil {
		return out, err
	}
	_ = host
	prof, err := policy.Get(req.Profile)
	if err != nil {
		return out, err
	}
	if prof.ApprovalRequired {
		return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "deep and incident-response fixture inspect still require a verified approval and are refused here"}
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
			return out, err
		}
		result := collectModule(ctx, req.Root, req.Now, collector.Request{
			ScanID: req.ScanID, AttemptID: req.AttemptID, HostID: req.HostID,
			ModuleID: module, Profile: req.Profile, PolicyVersion: policy.PolicyVersion,
			Limits: collector.Limits{Timeout: moduleTimeout, MaxRecords: 4096, MaxBytes: prof.Limits.MaxFileSizeBytes},
		})
		out.Modules = append(out.Modules, result)
		if err := putResult(ctx, store, req, result); err != nil {
			return out, err
		}
	}
	if _, err := store.BuildManifest(ctx, req.ScanID, policy.PolicyVersion); err != nil {
		return out, err
	}
	reportVerify, err := store.Verify(ctx, req.ScanID)
	if err != nil {
		return out, err
	}
	out.Integrity = reportVerify
	items, err := store.List(ctx, req.ScanID)
	if err != nil {
		return out, err
	}
	bundle, err := rules.Load(rules.DefaultBundle)
	if err != nil {
		return out, err
	}
	base := baseline.Candidate(req.HostID, req.ScanID)
	basePath := filepath.Join(req.OutDir, "baseline-candidate.json")
	_ = baseline.Save(basePath, base)
	results, findings, err := rules.Evaluate(ctx, req.ScanID, req.HostID, req.Profile, items, base, bundle)
	if err != nil {
		return out, err
	}
	results = rejectPassOnFailedCollection(results, out.Modules)
	out.RuleResults = results
	out.Findings = findings
	out.Evidence = items
	out.JobStatus, out.JobStatusReason = labJobStatus(out.Modules)
	exec := tools.Executor{}
	for _, tool := range prof.Tools {
		rep, toolErr := adapter.Lynis(ctx, exec, req.HostID, req.ScanID)
		if tool != tools.ToolLynis {
			rep, toolErr = runNamed(ctx, exec, tool, req.HostID, req.ScanID)
		}
		if toolErr != nil {
			return out, toolErr
		}
		out.ToolReports = append(out.ToolReports, rep)
	}
	out.Intel = intel.Correlate(items, nil)
	doc := report.BuildFromInput(reportInput(out, bundle))
	path, err := report.Write(req.OutDir, doc)
	if err != nil {
		return out, err
	}
	out.ReportPath = path
	return out, nil
}

func runNamed(ctx context.Context, exec tools.Executor, tool, hostID, scanID string) (adapter.Report, error) {
	switch tool {
	case tools.ToolYARA:
		return adapter.YARA(ctx, exec, hostID, scanID)
	case tools.ToolOsquery:
		return adapter.Osquery(ctx, exec, hostID, scanID)
	case tools.ToolOpenSCAP:
		return adapter.OpenSCAP(ctx, exec, hostID, scanID)
	case tools.ToolClamAV:
		return adapter.ClamAV(ctx, exec, hostID, scanID)
	default:
		return adapter.Lynis(ctx, exec, hostID, scanID)
	}
}

func authorizedHost(inv asset.Inventory, hostID, profile string) (asset.Host, error) {
	for _, host := range inv.Hosts {
		if host.ID != hostID {
			continue
		}
		if !asset.IsAuthorized(host) {
			return asset.Host{}, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "host is not authorized"}
		}
		allowed := false
		for _, name := range host.AllowedProfiles {
			if name == profile {
				allowed = true
				break
			}
		}
		if !allowed {
			return asset.Host{}, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "profile is not allowed for host"}
		}
		return host, nil
	}
	return asset.Host{}, &domain.Error{Code: domain.CodeInvalidID, Message: "host is unknown"}
}

func collectModule(ctx context.Context, root string, now func() time.Time, req collector.Request) collector.Result {
	return linux.CollectModule(ctx, root, false, now, req)
}

func putResult(ctx context.Context, store *evidence.Store, req Request, result collector.Result) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	normalized := map[string]any{"module": result.ModuleID, "status": result.Status, "completeness": result.Completeness, "records": result.Records, "warnings": result.Warnings}
	if len(result.Records) == 1 {
		for key, value := range result.Records[0] {
			if _, exists := normalized[key]; !exists {
				normalized[key] = value
			}
		}
	}
	status := result.Status
	completeness := result.Completeness
	if status == "" {
		status = domain.CollectionFailed
	}
	in := evidence.Input{
		EvidenceID: "evidence-" + strings.ReplaceAll(result.ModuleID, "_", "-"),
		HostID:     req.HostID, ScanID: req.ScanID, AttemptID: req.AttemptID,
		CollectedAt: req.Now().UTC(), Module: result.ModuleID, CollectorVersion: collector.Version,
		Category: categoryFor(result.ModuleID), RawSummary: result.ModuleID + " fixture inspect",
		CollectionStatus: status, Completeness: completeness, Warnings: result.Warnings,
		Normalized: normalized,
	}
	if status == domain.CollectionSuccess {
		in.Raw = raw
	} else if len(result.Records) > 0 {
		in.Raw = raw
		if status == domain.CollectionSuccess {
			in.CollectionStatus = domain.CollectionSuccess
		}
	}
	if in.CollectionStatus == domain.CollectionSuccess && in.Completeness != domain.CompletenessComplete {
		in.CollectionStatus = domain.CollectionPartial
	}
	if in.Completeness == "" {
		in.Completeness = domain.CompletenessUnavailable
	}
	if in.Warnings == nil {
		in.Warnings = []string{}
	}
	_, err = store.Put(ctx, in)
	return err
}

func categoryFor(module string) string {
	switch module {
	case linux.ModuleProcessInventory:
		return "process"
	case linux.ModuleNetworkInventory:
		return "network"
	case linux.ModuleAccountInventory:
		return "identity"
	case linux.ModuleServiceInventory, linux.ModulePersistenceInventory:
		return "persistence"
	case linux.ModuleSecurityConfig:
		return "config"
	case linux.ModulePackageInventory:
		return "package"
	case linux.ModuleTargetedFileScan:
		return "malware"
	default:
		return "host"
	}
}
