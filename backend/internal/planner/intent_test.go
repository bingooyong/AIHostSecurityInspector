package planner

import (
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestBuildIntentAndPreflightStayNotReady(t *testing.T) {
	inv := inventory(t)
	intent, err := BuildIntent(t.Context(), inv, IntentRequest{
		HostID: "linux-test-001", Profile: "quick", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-20T00:00:00Z", ValidUntil: "2026-11-20T04:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if intent.Mode != domain.ModeReadOnly {
		t.Fatal("intent escaped read-only")
	}
	result, err := Preflight(t.Context(), inv, intent, approval.TrustStore{}, nil, func() time.Time {
		return time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC)
	}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExecutionReady || result.CollectorAvailable || result.LimitsEnforced {
		t.Fatal("preflight claimed execution")
	}
}

func TestPreflightRejectsSnapshotDriftAndMissingDeepApproval(t *testing.T) {
	inv := inventory(t)
	intent, err := BuildIntent(t.Context(), inv, IntentRequest{
		HostID: "linux-test-001", Profile: "deep", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-20T00:00:00Z", ValidUntil: "2026-11-20T04:00:00Z",
		Window: &domain.MaintenanceWindow{Timezone: "UTC", Start: "2026-11-20T01:00:00Z", End: "2026-11-20T03:00:00Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 11, 20, 1, 30, 0, 0, time.UTC) }
	if _, err := Preflight(t.Context(), inv, intent, approval.TrustStore{}, nil, clock, nil, false); err == nil {
		t.Fatal("deep preflight without approval")
	}
	changed := inv
	changed.Hosts = append([]asset.Host{}, inv.Hosts...)
	falseVal := false
	host := changed.Hosts[0]
	host.Authorized = &falseVal
	changed.Hosts[0] = host
	quick, err := BuildIntent(t.Context(), inv, IntentRequest{
		HostID: "linux-test-001", Profile: "quick", RequesterPrincipal: "operator-alice",
		ValidFrom: "2026-11-20T00:00:00Z", ValidUntil: "2026-11-20T04:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Preflight(t.Context(), changed, quick, approval.TrustStore{}, nil, clock, nil, false); err == nil {
		t.Fatal("drifted assets accepted")
	}
}
