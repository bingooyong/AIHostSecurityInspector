package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/app"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
)

func TestMCPToolsListAndRejectForbidden(t *testing.T) {
	srv := testServer(t, "operator-alice")
	out := call(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if !strings.Contains(out, "list_authorized_hosts") || strings.Contains(out, "execute_shell") || strings.Contains(out, "ssh_exec") {
		t.Fatalf("tool catalog leaked forbidden tools: %s", out)
	}
	denied := call(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_shell","arguments":{}}}`+"\n")
	if !strings.Contains(denied, "AUTH_DENIED") {
		t.Fatalf("forbidden tool not denied: %s", denied)
	}
	hosts := call(t, srv, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_authorized_hosts","arguments":{}}}`+"\n")
	if !strings.Contains(hosts, "linux-test-001") || strings.Contains(hosts, "linux-denied-001") {
		t.Fatalf("host list leaked unauthorized assets: %s", hosts)
	}
	role := call(t, srv, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_authorized_hosts","arguments":{"role":"admin"}}}`+"\n")
	if !strings.Contains(role, "AUTH_DENIED") {
		t.Fatalf("self-asserted role accepted: %s", role)
	}
}

func TestMCPFixtureInspectAndCrossZone(t *testing.T) {
	srv := testServer(t, "operator-alice")
	root := filepath.Join("..", "collector", "linux", "testdata", "host")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	srv.Service.FixtureRoot = abs
	srv.Service.OutDir = t.TempDir()
	plan := call(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"plan_host_scan","arguments":{"host_id":"linux-test-001","profile":"quick"}}}`+"\n")
	var wrapped struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(plan), &wrapped); err != nil {
		t.Fatal(plan, err)
	}
	var rec app.PlanRecord
	if err := json.Unmarshal([]byte(wrapped.Result.Content[0].Text), &rec); err != nil {
		t.Fatal(err)
	}
	run := call(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_host_scan","arguments":{"plan_id":"`+rec.PlanID+`","idempotency_key":"k1"}}}`+"\n")
	if strings.Contains(run, `"scan_ready": true`) || strings.Contains(run, `"collector_available": true`) || strings.Contains(run, `"execution_ready": true`) {
		t.Fatalf("fixture inspect claimed live scan: %s", run)
	}
	if !strings.Contains(run, "scan-local-") {
		t.Fatalf("missing scan id: %s", run)
	}
	foreign := testServer(t, "operator-zone-b")
	cross := call(t, foreign, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"plan_host_scan","arguments":{"host_id":"linux-test-001","profile":"quick"}}}`+"\n")
	if !strings.Contains(cross, "HOST_NOT_AUTHORIZED") {
		t.Fatalf("cross-zone plan accepted: %s", cross)
	}
	auditor := testServer(t, "auditor-carol")
	blocked := call(t, auditor, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_host_scan","arguments":{"host_id":"linux-test-001","profile":"quick"}}}`+"\n")
	if !strings.Contains(blocked, "AUTH_DENIED") {
		t.Fatalf("auditor ran a scan: %s", blocked)
	}
}

func testServer(t *testing.T, principal string) Server {
	t.Helper()
	inv, err := asset.Load(context.Background(), "../../../examples/hosts.yaml")
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
	caller, err := dir.Lookup(principal)
	if err != nil {
		t.Fatal(err)
	}
	return Server{Service: app.New(*inv, dir), Caller: caller}
}

func call(t *testing.T, srv Server, line string) string {
	t.Helper()
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), strings.NewReader(line), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
