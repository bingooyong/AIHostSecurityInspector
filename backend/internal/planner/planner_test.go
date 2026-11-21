package planner

import (
	"context"
	"os"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
)

func inventory(t *testing.T) asset.Inventory {
	t.Helper()
	b, e := os.ReadFile("../../../examples/hosts.yaml")
	if e != nil {
		t.Fatal(e)
	}
	inv, e := asset.Parse(context.Background(), b)
	if e != nil {
		t.Fatal(e)
	}
	return *inv
}
func TestFourOfflineProfiles(t *testing.T) {
	inv := inventory(t)
	for _, profile := range []string{"quick", "standard", "deep", "incident-response"} {
		t.Run(profile, func(t *testing.T) {
			p, e := Build(context.Background(), inv, Request{Targets: "group:pilot", Profile: profile, DryRun: true})
			if e != nil {
				t.Fatal(e)
			}
			if p.ExecutionReady || !p.DryRun || p.Mode != "READ_ONLY" || p.Limits.Enforced || len(p.Hosts) != 1 {
				t.Fatal("unsafe plan")
			}
			if p.ApprovalRequired != (profile == "deep" || profile == "incident-response") {
				t.Fatal("approval requirement wrong")
			}
			if len(p.Modules) < 4 || len(p.Limitations) == 0 {
				t.Fatal("plan missing coverage")
			}
		})
	}
}
func TestAtomicAuthorizationAndSelectors(t *testing.T) {
	inv := inventory(t)
	requests := []Request{
		{Targets: "group:mixed", Profile: "quick", DryRun: true},
		{HostID: "linux-denied-001", Profile: "quick", DryRun: true},
		{HostID: "192.0.2.10", Profile: "quick", DryRun: true},
		{HostID: "linux-test-001;touch", Profile: "quick", DryRun: true},
		{Targets: "192.0.2.0/24", Profile: "quick", DryRun: true},
		{Targets: "group:missing", Profile: "quick", DryRun: true},
		{HostID: "linux-test-001", Targets: "group:pilot", Profile: "quick", DryRun: true},
		{HostID: "linux-test-001", Profile: "quick"},
		{HostID: "linux-test-001", Profile: "command", DryRun: true},
	}
	for _, req := range requests {
		p, e := Build(context.Background(), inv, req)
		if e == nil || p != nil {
			t.Fatal("unsafe request produced plan", req)
		}
	}
	inv.Hosts[0].AllowedProfiles = []string{"quick"}
	if p, e := Build(context.Background(), inv, Request{HostID: "linux-test-001", Profile: "deep", DryRun: true}); e == nil || p != nil {
		t.Fatal("unauthorized profile accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Build(ctx, inv, Request{HostID: "linux-test-001", Profile: "quick", DryRun: true}); e != context.Canceled {
		t.Fatal("cancellation ignored")
	}
}

func TestValidateOfflinePlanRejectsReady(t *testing.T) {
	inv := inventory(t)
	plan, err := Build(context.Background(), inv, Request{Targets: "group:pilot", Profile: "quick", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOfflinePlan(*plan); err != nil {
		t.Fatal(err)
	}
	plan.ExecutionReady = true
	if err := ValidateOfflinePlan(*plan); err == nil {
		t.Fatal("execution-ready offline plan accepted")
	}
}
