package orchestrator

import (
	"context"
	"path/filepath"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
)

// AuthorizedRequest is a user-operated collection run over explicitly
// allowlisted, inventory-authorized loopback lab targets. It is not a
// general intranet scanner and never flips product readiness flags.
type AuthorizedRequest struct {
	Inventory  asset.Inventory
	Allowlist  authorization.CollectionAllowlist
	Bindings   authorization.CollectionBindings
	Intent     domain.ExecutionIntent
	Approval   *approval.Document
	TrustStore approval.TrustStore
	Profile    string
	OutDir     string
	Now        func() time.Time
}

// AuthorizedResult aggregates per-host lab collection results.
type AuthorizedResult struct {
	SchemaVersion      string   `json:"schema_version"`
	Profile            string   `json:"profile"`
	IntentHash         string   `json:"intent_hash"`
	Hosts              []Result `json:"hosts"`
	CollectorAvailable bool     `json:"collector_available"`
	ScanReady          bool     `json:"scan_ready"`
	ExecutionReady     bool     `json:"execution_ready"`
	Limitations        []string `json:"limitations"`
}

func defaultAuthorizedLimitations() []string {
	return []string{
		"authorized collection of explicitly allowlisted loopback lab hosts only",
		"not a general intranet scanner and not enterprise host scanning",
		"inventory authorization is not enough without a matching allowlist and intent",
		"doctor collector_available and scan_ready remain false",
		"local identity or local CA is not a platform IdP",
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
	if req.Approval != nil || len(req.TrustStore.Principals) > 0 {
		preflight, preflightErr := planner.Preflight(ctx, req.Inventory, req.Intent, req.TrustStore, req.Approval, req.Now, nil, nil, false)
		if preflightErr != nil {
			return out, preflightErr
		}
		if preflight.ExecutionReady || preflight.CollectorAvailable {
			return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "preflight must not mark execution or collector ready"}
		}
	}
	for _, item := range prepared {
		if err := ctx.Err(); err != nil {
			return out, err
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
			return out, inspectErr
		}
		out.Hosts = append(out.Hosts, result)
	}
	if out.CollectorAvailable || out.ScanReady || out.ExecutionReady {
		return out, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "authorized collection must not mark product scan ready"}
	}
	return out, nil
}
