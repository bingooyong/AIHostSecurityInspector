// Package planner turns validated authorized assets into offline plans.
package planner

import (
	"context"
	"errors"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
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
	if !req.DryRun || (req.HostID == "") == (req.Targets == "") {
		return nil, errors.New("exactly one target selector and dry-run are required")
	}
	p, err := policy.Get(req.Profile)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	if req.HostID != "" {
		if !asset.ValidID(req.HostID) {
			return nil, errors.New("invalid target selector")
		}
		ids = append(ids, req.HostID)
	} else {
		if !strings.HasPrefix(req.Targets, "group:") {
			return nil, errors.New("invalid target selector")
		}
		name := strings.TrimPrefix(req.Targets, "group:")
		g, ok := inv.Groups[name]
		if !asset.ValidID(name) || !ok || len(g.Hosts) == 0 {
			return nil, errors.New("unknown or empty target group")
		}
		ids = g.Hosts
	}
	byID := make(map[string]asset.Host, len(inv.Hosts))
	for _, h := range inv.Hosts {
		byID[h.ID] = h
	}
	targets := make([]Target, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, ok := byID[id]
		if !ok || !asset.IsAuthorized(h) {
			return nil, errors.New("host not authorized")
		}
		allowed := false
		for _, name := range h.AllowedProfiles {
			if name == p.Name {
				allowed = true
			}
		}
		if !allowed {
			return nil, errors.New("profile not authorized")
		}
		targets = append(targets, Target{HostID: h.ID, Addresses: append([]string{}, h.Addresses...), Transport: h.Connection.Transport, Environment: h.Environment})
	}
	return &Plan{SchemaVersion: "1.0", Mode: "READ_ONLY", DryRun: true, Profile: p.Name, Hosts: targets, Modules: p.Modules, Tools: p.Tools, ApprovalRequired: p.ApprovalRequired, ExecutionReady: false, Limits: p.Limits, EstimatedImpact: p.EstimatedImpact, Limitations: []string{"No collector, transport, approval verifier, rule evaluation, evidence collection, or AI call has run.", "Profiles and limits are fixed planning descriptions; execution enforcement is not implemented.", "Deep and incident-response execution require a verified approval bound to the plan and a maintenance window.", "Vulnerability intelligence, trusted baselines and scanner availability have not been checked.", "No findings or safety assessment can be inferred from this offline plan."}}, nil
}
