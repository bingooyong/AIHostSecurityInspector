package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/app"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
)

func TestAPILoopbackRBACAndIDOR(t *testing.T) {
	if err := ListenAllowed("0.0.0.0:8080"); err == nil {
		t.Fatal("non-loopback listen allowed")
	}
	if err := ListenAllowed("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	inv, err := asset.Load(t.Context(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../../examples/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := authorization.ParseDirectory(raw)
	if err != nil {
		t.Fatal(err)
	}
	svc := app.New(*inv, dir)
	abs, err := filepath.Abs(filepath.Join("..", "collector", "linux", "testdata", "host"))
	if err != nil {
		t.Fatal(err)
	}
	svc.FixtureRoot = abs
	svc.OutDir = t.TempDir()
	handler := New(svc, dir).Handler()
	req := httptest.NewRequest(http.MethodGet, "/v1/hosts", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing identity accepted: %d %s", rec.Code, rec.Body.String())
	}
	hosts := do(t, handler, http.MethodGet, "/v1/hosts", "operator-alice", nil)
	if hosts.Code != 200 || !bytes.Contains(hosts.Body.Bytes(), []byte("linux-test-001")) {
		t.Fatalf("operator hosts: %s", hosts.Body.String())
	}
	plan := do(t, handler, http.MethodPost, "/v1/plans", "operator-alice", map[string]string{"host_id": "linux-test-001", "profile": "quick"})
	if plan.Code != 200 {
		t.Fatal(plan.Body.String())
	}
	var recPlan app.PlanRecord
	if err := json.Unmarshal(plan.Body.Bytes(), &recPlan); err != nil {
		t.Fatal(err)
	}
	scan := do(t, handler, http.MethodPost, "/v1/scans", "operator-alice", map[string]string{"plan_id": recPlan.PlanID, "idempotency_key": "k1"})
	if scan.Code != 200 || bytes.Contains(scan.Body.Bytes(), []byte(`"scan_ready": true`)) {
		t.Fatalf("scan: %s", scan.Body.String())
	}
	var payload struct {
		Job struct {
			ScanID string `json:"scan_id"`
		} `json:"job"`
	}
	if err := json.Unmarshal(scan.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	stolen := do(t, handler, http.MethodGet, "/v1/scans/"+payload.Job.ScanID, "operator-zone-b", nil)
	if stolen.Code != http.StatusForbidden {
		t.Fatalf("IDOR allowed: %d %s", stolen.Code, stolen.Body.String())
	}
	role := do(t, handler, http.MethodPost, "/v1/plans", "operator-alice", map[string]any{"host_id": "linux-test-001", "profile": "quick", "role": "admin"})
	if role.Code != http.StatusForbidden {
		t.Fatalf("self-asserted role accepted: %s", role.Body.String())
	}
}

func do(t *testing.T, handler http.Handler, method, path, principal string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	if principal != "" {
		req.Header.Set("X-HostSec-Principal", principal)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
