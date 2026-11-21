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

type PreflightInput struct {
	Inventory    asset.Inventory
	Intent       domain.ExecutionIntent
	Store        approval.TrustStore
	Document     *approval.Document
	Now          approval.Clock
	Journal      *audit.Journal
	Ledger       *approval.Ledger
	Consume      bool
	Capabilities map[string]bool
}

func Preflight(ctx context.Context, inv asset.Inventory, intent domain.ExecutionIntent, store approval.TrustStore, doc *approval.Document, now approval.Clock, journal *audit.Journal, ledger *approval.Ledger, consume bool) (PreflightResult, error) {
	return PreflightCheck(ctx, PreflightInput{
		Inventory: inv, Intent: intent, Store: store, Document: doc, Now: now, Journal: journal, Ledger: ledger, Consume: consume,
	})
}

func PreflightCheck(ctx context.Context, in PreflightInput) (PreflightResult, error) {
	if err := ctx.Err(); err != nil {
		return PreflightResult{}, err
	}
	if in.Now == nil {
		return PreflightResult{}, errors.New("clock is required")
	}
	if err := in.Intent.Validate(); err != nil {
		return PreflightResult{}, err
	}
	if err := asset.Revalidate(in.Intent.AssetSnapshotHash, in.Inventory); err != nil {
		return PreflightResult{Reasons: []string{"asset snapshot drifted"}}, err
	}
	if err := revalidatePolicy(in.Intent); err != nil {
		return PreflightResult{Reasons: []string{err.Error()}}, err
	}
	hash, err := domain.HashExecutionIntent(in.Intent)
	if err != nil {
		return PreflightResult{}, err
	}
	result := PreflightResult{
		IntentHash:         hash,
		AssetSnapshotHash:  in.Intent.AssetSnapshotHash,
		CollectorAvailable: false,
		LimitsEnforced:     false,
		ExecutionReady:     false,
		Reasons:            []string{"Linux collector is not available; preflight cannot mark execution ready.", "Resource limits are described but not enforced by a running scanner."},
	}
	if reasons, err := checkCapabilities(in.Intent.RequiredCapabilities, in.Capabilities); err != nil {
		result.Reasons = append(result.Reasons, reasons...)
		return result, err
	} else {
		result.Reasons = append(result.Reasons, reasons...)
	}
	if domain.ProfileRequiresApproval(in.Intent.Profile) {
		if in.Document == nil {
			result.Reasons = append(result.Reasons, "deep and incident-response require a verified approval")
			return result, approval.ErrInvalid
		}
		verified, err := approval.Verify(in.Store, *in.Document, in.Intent, in.Now())
		if err != nil {
			return result, err
		}
		result.ApprovalVerified = true
		if in.Consume {
			if in.Journal == nil {
				return result, errors.New("audit journal is required to consume an approval")
			}
			if in.Ledger == nil {
				return result, errors.New("nonce ledger is required to consume an approval")
			}
			event := audit.Event{EventID: "consume-" + verified.Document.ApprovalID, At: in.Now().UTC().Format(domain.TimeLayout), Decision: "allow"}
			if err := in.Journal.ConsumeAndAudit(verified, event); err != nil {
				return result, err
			}
			if err := in.Ledger.Consume(verified.Document.Nonce); err != nil {
				return result, err
			}
		} else {
			result.Reasons = append(result.Reasons, "approval verified without consumption; planning is not an execution grant")
		}
	}
	return result, nil
}

func revalidatePolicy(intent domain.ExecutionIntent) error {
	if intent.PolicyID != policy.PolicyID || intent.PolicyVersion != policy.PolicyVersion {
		return errors.New("policy identity drifted")
	}
	current, err := policy.CurrentHash(intent.Profile)
	if err != nil {
		return err
	}
	if current != intent.PolicyHash {
		return errors.New("policy hash drifted")
	}
	return nil
}

func checkCapabilities(required []string, available map[string]bool) ([]string, error) {
	if available == nil {
		return []string{"required capabilities have not been probed; unknown is not available"}, nil
	}
	var missing []string
	for _, name := range required {
		if !available[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return []string{"required capability is unavailable: " + fmt.Sprintf("%v", missing)}, errors.New("required capability is unavailable")
	}
	return []string{"declared capabilities were present in the preflight inventory"}, nil
}

func FormatIdentityRef(hostID string) string {
	return fmt.Sprintf("hostid-%s", hostID)
}
