package planner

import (
	"context"
	"errors"
	"fmt"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/audit"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

type IntentRequest struct {
	HostID, Targets, Profile string
	RequesterPrincipal       string
	ValidFrom, ValidUntil    string
	Window                   *domain.MaintenanceWindow
}

type PreflightResult struct {
	IntentHash         string   `json:"intent_hash"`
	AssetSnapshotHash  string   `json:"asset_snapshot_hash"`
	ApprovalVerified   bool     `json:"approval_verified"`
	ExecutionReady     bool     `json:"execution_ready"`
	CollectorAvailable bool     `json:"collector_available"`
	LimitsEnforced     bool     `json:"limits_enforced"`
	Reasons            []string `json:"reasons"`
}

func BuildIntent(ctx context.Context, inv asset.Inventory, req IntentRequest) (domain.ExecutionIntent, error) {
	if err := ctx.Err(); err != nil {
		return domain.ExecutionIntent{}, err
	}
	hosts, profile, err := authorization.Select(ctx, inv, req.HostID, req.Targets, req.Profile)
	if err != nil {
		return domain.ExecutionIntent{}, err
	}
	snapshotHash, err := asset.HashSnapshot(inv)
	if err != nil {
		return domain.ExecutionIntent{}, err
	}
	policyHash, err := policy.Hash(profile)
	if err != nil {
		return domain.ExecutionIntent{}, err
	}
	hostIDs := make([]string, 0, len(hosts))
	identityRefs := make([]string, 0, len(hosts))
	for _, host := range hosts {
		hostIDs = append(hostIDs, host.ID)
		identityRefs = append(identityRefs, "hostid-"+host.ID)
	}
	intent := domain.ExecutionIntent{
		SchemaVersion:      domain.IntentSchemaVersion,
		CanonicalVersion:   domain.IntentCanonicalVersion,
		RequesterPrincipal: req.RequesterPrincipal,
		HostIDs:            hostIDs,
		IdentityRefs:       identityRefs,
		AssetSnapshotHash:  snapshotHash,
		PolicyID:           policy.PolicyID,
		PolicyVersion:      policy.PolicyVersion,
		PolicyHash:         policyHash,
		Profile:            profile.Name,
		Modules:            append([]string{}, profile.Modules...),
		Tools:              append([]string{}, profile.Tools...),
		AllowedPaths:       append([]string{}, profile.Limits.AllowedPaths...),
		ExcludedPaths:      append([]string{}, profile.Limits.ExcludedPaths...),
		ExcludedMountTypes: append([]string{}, profile.Limits.ExcludedMountTypes...),
		Limits: domain.IntentLimits{
			TimeoutSeconds:            profile.Limits.TimeoutSeconds,
			MaxConcurrency:            profile.Limits.MaxConcurrency,
			MaxFiles:                  profile.Limits.MaxFiles,
			MaxFileSizeBytes:          profile.Limits.MaxFileSizeBytes,
			IOMaxBytesPerSecond:       profile.Limits.IOMaxBytesPerSecond,
			StopOnResourcePressure:    profile.Limits.StopOnResourcePressure,
			MaintenanceWindowRequired: profile.Limits.MaintenanceWindowRequired,
		},
		RequiredCapabilities: requiredCapabilities(profile),
		ValidFrom:            req.ValidFrom,
		ValidUntil:           req.ValidUntil,
		MaintenanceWindow:    req.Window,
		Mode:                 domain.ModeReadOnly,
	}
	if err := intent.Validate(); err != nil {
		return domain.ExecutionIntent{}, err
	}
	return intent, nil
}

func requiredCapabilities(profile policy.Profile) []string {
	caps := []string{"linux_proc"}
	for _, module := range profile.Modules {
		if module == "targeted_file_scan" || module == "file_integrity" {
			caps = append(caps, "linux_file_meta")
			break
		}
	}
	return caps
}

func Preflight(ctx context.Context, inv asset.Inventory, intent domain.ExecutionIntent, store approval.TrustStore, doc *approval.Document, now approval.Clock, journal *audit.Journal, ledger *approval.Ledger, consume bool) (PreflightResult, error) {
	if err := ctx.Err(); err != nil {
		return PreflightResult{}, err
	}
	if now == nil {
		return PreflightResult{}, errors.New("clock is required")
	}
	if err := intent.Validate(); err != nil {
		return PreflightResult{}, err
	}
	if err := asset.Revalidate(intent.AssetSnapshotHash, inv); err != nil {
		return PreflightResult{Reasons: []string{"asset snapshot drifted"}}, err
	}
	hash, err := domain.HashExecutionIntent(intent)
	if err != nil {
		return PreflightResult{}, err
	}
	result := PreflightResult{
		IntentHash:         hash,
		AssetSnapshotHash:  intent.AssetSnapshotHash,
		CollectorAvailable: false,
		LimitsEnforced:     false,
		ExecutionReady:     false,
		Reasons:            []string{"Linux collector is not available; preflight cannot mark execution ready.", "Resource limits are described but not enforced by a running scanner."},
	}
	if domain.ProfileRequiresApproval(intent.Profile) {
		if doc == nil {
			result.Reasons = append(result.Reasons, "deep and incident-response require a verified approval")
			return result, approval.ErrInvalid
		}
		verified, err := approval.Verify(store, *doc, intent, now())
		if err != nil {
			return result, err
		}
		result.ApprovalVerified = true
		if consume {
			if journal == nil {
				return result, errors.New("audit journal is required to consume an approval")
			}
			if ledger == nil {
				return result, errors.New("nonce ledger is required to consume an approval")
			}
			event := audit.Event{EventID: "consume-" + verified.Document.ApprovalID, At: now().UTC().Format(domain.TimeLayout), Decision: "allow"}
			if err := journal.ConsumeAndAudit(verified, event); err != nil {
				return result, err
			}
			if err := ledger.Consume(verified.Document.Nonce); err != nil {
				return result, err
			}
		} else {
			result.Reasons = append(result.Reasons, "approval verified without consumption; planning is not an execution grant")
		}
	}
	return result, nil
}

func FormatIdentityRef(hostID string) string {
	return fmt.Sprintf("hostid-%s", hostID)
}
