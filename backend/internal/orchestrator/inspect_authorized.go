package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/adapter"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/audit"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

// AuthorizedRequest is a user-operated collection run over explicitly
// allowlisted, inventory-authorized loopback lab targets. It is not a
// general intranet scanner and never flips product readiness flags.
type AuthorizedRequest struct {
	Inventory       asset.Inventory
	Allowlist       authorization.CollectionAllowlist
	Bindings        authorization.CollectionBindings
	Intent          domain.ExecutionIntent
	Approval        *approval.Document
	TrustStore      approval.TrustStore
	Journal         *audit.Journal
	ApprovalLedger  *approval.Ledger
	ConsumeApproval bool
	IntentLedger    *approval.Ledger
	Pressure        PressureSource
	Profile         string
	OutDir          string
	Now             func() time.Time
}

// AuthorizedHostSummary is the durable per-host record written to the
// aggregate authorized-collection report. It omits raw evidence payloads.
type AuthorizedHostSummary struct {
	HostID             string `json:"host_id"`
	JobStatus          string `json:"job_status"`
	JobStatusReason    string `json:"job_status_reason,omitempty"`
	ReportPath         string `json:"report_path,omitempty"`
	ModulesSuccess     int    `json:"modules_success"`
	ModulesPartial     int    `json:"modules_partial"`
	ModulesFailed      int    `json:"modules_failed"`
	ModulesTimeout     int    `json:"modules_timeout"`
	ModulesCancelled   int    `json:"modules_cancelled"`
	IntegrityOK        bool   `json:"integrity_ok"`
	ToolReports        int    `json:"tool_reports"`
	CollectorAvailable bool   `json:"collector_available"`
	ScanReady          bool   `json:"scan_ready"`
	ExecutionReady     bool   `json:"execution_ready"`
	Collected          bool   `json:"collected"`
}

// AuthorizedResult aggregates per-host lab collection results.
type AuthorizedResult struct {
	SchemaVersion      string                  `json:"schema_version"`
	Profile            string                  `json:"profile"`
	IntentHash         string                  `json:"intent_hash"`
	JobStatus          string                  `json:"job_status"`
	JobStatusReason    string                  `json:"job_status_reason,omitempty"`
	ReportPath         string                  `json:"report_path,omitempty"`
	Hosts              []Result                `json:"hosts"`
	HostSummaries      []AuthorizedHostSummary `json:"host_summaries"`
	ToolReports        []adapter.Report        `json:"tool_reports,omitempty"`
	CollectorAvailable bool                    `json:"collector_available"`
	ScanReady          bool                    `json:"scan_ready"`
	ExecutionReady     bool                    `json:"execution_ready"`
	Limitations        []string                `json:"limitations"`
}

func defaultAuthorizedLimitations() []string {
	return []string{
		"authorized collection of explicitly allowlisted loopback lab hosts only",
		"not a general intranet scanner and not enterprise host scanning",
		"inventory authorization is not enough without a matching allowlist and intent",
		"doctor collector_available and scan_ready remain false",
		"local identity or local CA is not a platform IdP",
		"a fully successful lab collection stays PARTIAL and is not a production completed scan",
		"an intent-ledger, when provided, is consumed after a successful prepare and cannot be replayed",
		"official tool adapters run on this lab control host only when HOSTSEC_LIVE_TOOLS=1 and are not remote SSH tool execution",
	}
}

// InspectAuthorized prepares and collects from every allowlisted host.
// Preparation is fail-closed: one unauthorized or misbound host rejects the run
// before any collection starts.
func InspectAuthorized(ctx context.Context, req AuthorizedRequest) (AuthorizedResult, error) {
	out := AuthorizedResult{
		SchemaVersion:      "1.0",
		Profile:            req.Profile,
		CollectorAvailable: false,
		ScanReady:          false,
		ExecutionReady:     false,
		Hosts:              []Result{},
		HostSummaries:      []AuthorizedHostSummary{},
		Limitations:        defaultAuthorizedLimitations(),
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if req.OutDir == "" {
		return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "output directory is required"}
	}
	if req.Now == nil {
		req.Now = time.Now
	}
	prepared, err := PrepareAuthorizedCollection(ctx, CollectionPlanRequest{
		Inventory: req.Inventory, Allowlist: req.Allowlist, Bindings: req.Bindings,
		Intent: req.Intent, Profile: req.Profile,
	})
	if err != nil {
		return out, err
	}
	hash, err := domain.HashExecutionIntent(req.Intent)
	if err != nil {
		return out, err
	}
	out.IntentHash = hash
	out.Profile = req.Intent.Profile
	if req.Approval != nil || len(req.TrustStore.Principals) > 0 || req.ConsumeApproval {
		preflight, preflightErr := planner.Preflight(ctx, req.Inventory, req.Intent, req.TrustStore, req.Approval, req.Now, req.Journal, req.ApprovalLedger, req.ConsumeApproval)
		if preflightErr != nil {
			return out, preflightErr
		}
		if preflight.ExecutionReady || preflight.CollectorAvailable {
			return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "preflight must not mark execution or collector ready"}
		}
	}
	if err := consumeIntent(req.IntentLedger, hash); err != nil {
		return out, err
	}
	var stop error
	for i, item := range prepared {
		if err := ctx.Err(); err != nil {
			stop = err
			out.Hosts = append(out.Hosts, skippedAuthorizedHosts(prepared[i:], req.Intent.Profile, err)...)
			break
		}
		if err := beforeModule(ctx, req.Pressure, true); err != nil {
			stop = err
			out.Hosts = append(out.Hosts, skippedAuthorizedHosts(prepared[i:], req.Intent.Profile, err)...)
			break
		}
		hostOut := filepath.Join(req.OutDir, "hosts", item.Host.ID)
		inspectReq := Request{
			Inventory: req.Inventory, HostID: item.Host.ID, Profile: req.Intent.Profile,
			OutDir: hostOut, ScanID: "scan-lab-" + item.Host.ID, AttemptID: "attempt-lab-001",
			Now: req.Now, Live: true, SSH: item.SSH,
		}
		result, inspectErr := InspectLocal(ctx, inspectReq)
		if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
			return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "authorized collection must not mark product scan ready"}
		}
		if inspectErr != nil {
			if result.HostID == "" {
				result.HostID = item.Host.ID
			}
			if result.Profile == "" {
				result.Profile = req.Intent.Profile
			}
			if result.JobStatus == "" || result.JobStatus == domain.JobCreated {
				result.JobStatus, result.JobStatusReason = statusForStop(inspectErr)
			}
			out.Hosts = append(out.Hosts, result)
			if errors.Is(inspectErr, context.Canceled) || errors.Is(inspectErr, context.DeadlineExceeded) || errors.Is(inspectErr, ErrResourcePressure) {
				stop = inspectErr
				if i+1 < len(prepared) {
					out.Hosts = append(out.Hosts, skippedAuthorizedHosts(prepared[i+1:], req.Intent.Profile, inspectErr)...)
				}
				break
			}
			return finalizeAuthorized(out, req.OutDir, inspectErr)
		}
		out.Hosts = append(out.Hosts, result)
	}
	if tools.LiveToolsEnabled() && stop == nil && ctx.Err() == nil {
		out.ToolReports = runAuthorizedLabTools(ctx, "lab-loopback-control", "scan-lab-authorized-tools")
		out.Limitations = append(out.Limitations, "official tool adapters ran on the lab control host under HOSTSEC_LIVE_TOOLS; this is not remote tool execution on each SSH stand-in")
	}
	if out.CollectorAvailable || out.ScanReady || out.ExecutionReady {
		return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "authorized collection must not mark product scan ready"}
	}
	return finalizeAuthorized(out, req.OutDir, stop)
}

func consumeIntent(ledger *approval.Ledger, hash string) error {
	if ledger == nil {
		return nil
	}
	if hash == "" {
		return bindError("execution intent hash is required to consume the intent ledger")
	}
	if err := ledger.Consume(hash); err != nil {
		if errors.Is(err, approval.ErrReplay) {
			return bindError("execution intent was already consumed and cannot be replayed")
		}
		return err
	}
	return nil
}

func skippedAuthorizedHosts(items []PreparedHost, profile string, cause error) []Result {
	status, reason := statusForStop(cause)
	out := make([]Result, 0, len(items))
	for _, item := range items {
		out = append(out, Result{
			HostID: item.Host.ID, Profile: profile,
			CollectorAvailable: false, ScanReady: false, ExecutionReady: false,
			Modules: []collector.Result{}, JobStatus: status, JobStatusReason: reason,
			Limitations: []string{"host was not collected because the authorized job stopped before this target"},
		})
	}
	return out
}

func statusForStop(cause error) (string, string) {
	if errors.Is(cause, context.DeadlineExceeded) {
		return domain.JobFailed, "authorized job timed out before this host was collected; not a production completed scan"
	}
	if errors.Is(cause, ErrResourcePressure) {
		return domain.JobCancelled, "authorized job stopped under resource pressure before this host was collected; not a production completed scan"
	}
	return domain.JobCancelled, "authorized job cancelled before this host was collected; not a production completed scan"
}

func summarizeAuthorizedHost(result Result) AuthorizedHostSummary {
	success, partial, failed, timeout, cancelled := countModuleStatuses(result.Modules)
	return AuthorizedHostSummary{
		HostID:             result.HostID,
		JobStatus:          result.JobStatus,
		JobStatusReason:    result.JobStatusReason,
		ReportPath:         result.ReportPath,
		ModulesSuccess:     success,
		ModulesPartial:     partial,
		ModulesFailed:      failed,
		ModulesTimeout:     timeout,
		ModulesCancelled:   cancelled,
		IntegrityOK:        result.Integrity.OK,
		ToolReports:        len(result.ToolReports),
		CollectorAvailable: result.CollectorAvailable,
		ScanReady:          result.ScanReady,
		ExecutionReady:     result.ExecutionReady,
		Collected:          result.ReportPath != "" || len(result.Modules) > 0,
	}
}

func aggregateAuthorizedStatus(hosts []Result) (string, string) {
	if len(hosts) == 0 {
		return domain.JobFailed, "no allowlisted hosts were collected"
	}
	cancelled, failed, collected, complete, incomplete := 0, 0, 0, 0, 0
	for _, host := range hosts {
		hasEvidence := host.ReportPath != "" || len(host.Modules) > 0
		if hasEvidence {
			collected++
		}
		switch host.JobStatus {
		case domain.JobCancelled:
			cancelled++
		case domain.JobFailed:
			failed++
		default:
			success, partial, failedMods, timeout, cancelledMods := countModuleStatuses(host.Modules)
			if host.JobStatus != domain.JobCompleted && cancelledMods == 0 && failedMods == 0 && timeout == 0 && partial == 0 && success > 0 {
				complete++
			} else {
				incomplete++
			}
		}
	}
	reason := "allowlisted lab hosts collected=" + strconv.Itoa(collected) + " complete=" + strconv.Itoa(complete) + " incomplete=" + strconv.Itoa(incomplete) + " failed=" + strconv.Itoa(failed) + " cancelled=" + strconv.Itoa(cancelled) + "; not a production completed scan"
	if cancelled > 0 {
		return domain.JobCancelled, reason
	}
	if failed == len(hosts) {
		return domain.JobFailed, reason
	}
	if complete == len(hosts) {
		return domain.JobPartial, "all allowlisted lab hosts collected successfully; status remains PARTIAL because this is not a production completed scan"
	}
	return domain.JobPartial, reason
}

func finalizeAuthorized(out AuthorizedResult, outDir string, stop error) (AuthorizedResult, error) {
	out.HostSummaries = make([]AuthorizedHostSummary, 0, len(out.Hosts))
	for _, host := range out.Hosts {
		if host.CollectorAvailable || host.ScanReady || host.ExecutionReady {
			return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "authorized collection must not mark product scan ready"}
		}
		out.HostSummaries = append(out.HostSummaries, summarizeAuthorizedHost(host))
	}
	out.CollectorAvailable = false
	out.ScanReady = false
	out.ExecutionReady = false
	out.JobStatus, out.JobStatusReason = aggregateAuthorizedStatus(out.Hosts)
	if out.JobStatus == domain.JobCompleted {
		out.JobStatus = domain.JobPartial
		out.JobStatusReason = "lab authorized collection cannot be a production completed scan"
	}
	path, err := writeAuthorizedReport(outDir, out)
	if err != nil {
		if stop != nil {
			return out, stop
		}
		return out, err
	}
	out.ReportPath = path
	return out, stop
}

func writeAuthorizedReport(outDir string, result AuthorizedResult) (string, error) {
	if outDir == "" || !filepath.IsAbs(outDir) {
		return "", &domain.Error{Code: domain.CodeInvalidCanonical, Message: "output directory is invalid"}
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", err
	}
	doc := struct {
		SchemaVersion      string                  `json:"schema_version"`
		Profile            string                  `json:"profile"`
		IntentHash         string                  `json:"intent_hash"`
		JobStatus          string                  `json:"job_status"`
		JobStatusReason    string                  `json:"job_status_reason,omitempty"`
		HostSummaries      []AuthorizedHostSummary `json:"host_summaries"`
		ToolReports        []adapter.Report        `json:"tool_reports,omitempty"`
		CollectorAvailable bool                    `json:"collector_available"`
		ScanReady          bool                    `json:"scan_ready"`
		ExecutionReady     bool                    `json:"execution_ready"`
		Limitations        []string                `json:"limitations"`
	}{
		SchemaVersion:      result.SchemaVersion,
		Profile:            result.Profile,
		IntentHash:         result.IntentHash,
		JobStatus:          result.JobStatus,
		JobStatusReason:    result.JobStatusReason,
		HostSummaries:      result.HostSummaries,
		ToolReports:        result.ToolReports,
		CollectorAvailable: false,
		ScanReady:          false,
		ExecutionReady:     false,
		Limitations:        result.Limitations,
	}
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(outDir, "authorized-collection.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(payload, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

func runAuthorizedLabTools(ctx context.Context, hostID, scanID string) []adapter.Report {
	exec := tools.Executor{}
	names := tools.Known()
	out := make([]adapter.Report, 0, len(names))
	for _, tool := range names {
		if err := ctx.Err(); err != nil {
			break
		}
		rep, err := runNamed(ctx, exec, tool, hostID, scanID)
		if err != nil {
			out = append(out, adapter.Report{Name: tool, Result: tools.Result{Tool: tool, Status: domain.CollectionFailed, Warning: "tool_adapter_error", Notes: []string{"official tool adapter returned an error and was not treated as a clean scan"}}})
			continue
		}
		out = append(out, rep)
	}
	return out
}
