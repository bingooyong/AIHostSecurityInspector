// Package planner turns validated authorized assets into offline plans.
package planner

import (
	"context"
	"errors"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

type Target struct {
	HostID      string   `json:"host_id"`
	Addresses   []string `json:"addresses"`
	Transport   string   `json:"transport"`
	Environment string   `json:"environment"`
}
type Plan struct {
	SchemaVersion    string        `json:"schema_version"`
	Mode             string        `json:"mode"`
	DryRun           bool          `json:"dry_run"`
	Profile          string        `json:"profile"`
	Hosts            []Target      `json:"hosts"`
	Modules          []string      `json:"modules"`
	Tools            []string      `json:"tools"`
	ApprovalRequired bool          `json:"approval_required"`
	ExecutionReady   bool          `json:"execution_ready"`
	Limits           policy.Limits `json:"limits"`
	EstimatedImpact  string        `json:"estimated_impact"`
	Limitations      []string      `json:"limitations"`
}

type Request struct {
	HostID, Targets, Profile string
	DryRun                   bool
}

func Build(ctx context.Context, inv asset.Inventory, req Request) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	if !req.DryRun {
		return nil, errors.New("exactly one target selector and dry-run are required")
	}
	hosts, p, err := authorization.Select(ctx, inv, req.HostID, req.Targets, req.Profile)
	if err != nil {
		return nil, err
	}
	targets := make([]Target, 0, len(hosts))
	for _, h := range hosts {
		targets = append(targets, Target{HostID: h.ID, Addresses: append([]string{}, h.Addresses...), Transport: h.Connection.Transport, Environment: h.Environment})
	}
	plan := &Plan{SchemaVersion: "1.0", Mode: "READ_ONLY", DryRun: true, Profile: p.Name, Hosts: targets, Modules: p.Modules, Tools: p.Tools, ApprovalRequired: p.ApprovalRequired, ExecutionReady: false, Limits: p.Limits, EstimatedImpact: p.EstimatedImpact, Limitations: []string{"No collector, transport, approval verifier, rule evaluation, evidence collection, or AI call has run.", "Profiles and limits are fixed planning descriptions; execution enforcement is not implemented.", "Deep and incident-response execution require a verified approval bound to the plan and a maintenance window.", "Vulnerability intelligence, trusted baselines and scanner availability have not been checked.", "No findings or safety assessment can be inferred from this offline plan."}}
	if err := ValidateOfflinePlan(*plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func ValidateOfflinePlan(plan Plan) error {
	if plan.SchemaVersion != "1.0" || plan.Mode != "READ_ONLY" || !plan.DryRun || plan.ExecutionReady || plan.Limits.Enforced {
		return errors.New("offline plan cannot claim execution")
	}
	if plan.ApprovalRequired != (plan.Profile == "deep" || plan.Profile == "incident-response") {
		return errors.New("approval_required does not match profile")
	}
	if len(plan.Hosts) == 0 {
		return errors.New("plan has no hosts")
	}
	return nil
}
