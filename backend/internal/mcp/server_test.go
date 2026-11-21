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

func TestMCPInitializeRequiredAndPaginatedTools(t *testing.T) {
	srv := testServer(t, "operator-alice")
	raw := callRaw(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if !strings.Contains(raw, "server not initialized") {
		t.Fatalf("tools/list before initialize accepted: %s", raw)
	}
	bad := callRaw(t, srv, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01","capabilities":{},"clientInfo":{"name":"hostsec-test","version":"0"}}}`+"\n")
	if !strings.Contains(bad, "unsupported protocolVersion") {
		t.Fatalf("bad protocol accepted: %s", bad)
	}
	extra := callRaw(t, srv, `{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"hostsec-test","version":"0"},"role":"admin"}}`+"\n")
	if !strings.Contains(extra, "initialize schema is invalid") {
		t.Fatalf("extra initialize field accepted: %s", extra)
	}
	first := call(t, srv, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`+"\n")
	if !strings.Contains(first, "list_authorized_hosts") || strings.Contains(first, "execute_shell") || strings.Contains(first, "ssh_exec") {
		t.Fatalf("tool catalog leaked forbidden tools: %s", first)
	}
	if !strings.Contains(first, `"nextCursor":"5"`) {
		t.Fatalf("expected tools pagination cursor: %s", first)
	}
	second := call(t, srv, `{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"cursor":"5"}}`+"\n")
	if !strings.Contains(second, "generate_scan_report") || strings.Contains(second, "nextCursor") {
		t.Fatalf("second tools page: %s", second)
	}
}

func TestMCPToolsListAndRejectForbidden(t *testing.T) {
	srv := testServer(t, "operator-alice")
	denied := call(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_shell","arguments":{}}}`+"\n")
	if !strings.Contains(denied, "AUTH_DENIED") {
		t.Fatalf("forbidden tool not denied: %s", denied)
	}
	hosts := call(t, srv, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_authorized_hosts","arguments":{"limit":1,"offset":0}}}`+"\n")
	firstPage := decodeTool[app.Page[app.PublicHost]](t, hosts)
	if firstPage.Total != 1 || len(firstPage.Items) != 1 || firstPage.Items[0].HostID != "linux-test-001" || strings.Contains(hosts, "auth_ref") {
		t.Fatalf("host list leaked unauthorized assets or connection refs: %s", hosts)
	}
	page := decodeTool[app.Page[app.PublicHost]](t, call(t, srv, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_authorized_hosts","arguments":{"limit":1,"offset":1}}}`+"\n"))
	if page.Total != 1 || len(page.Items) != 0 {
		t.Fatalf("host pagination failed: %+v", page)
	}
	role := call(t, srv, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_authorized_hosts","arguments":{"role":"admin"}}}`+"\n")
	if !strings.Contains(role, "AUTH_DENIED") {
		t.Fatalf("self-asserted role accepted: %s", role)
	}
}

func TestMCPFixtureInspectIdempotencyAndCrossZone(t *testing.T) {
	srv := testServer(t, "operator-alice")
	root := filepath.Join("..", "collector", "linux", "testdata", "host")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	srv.Service.FixtureRoot = abs
	srv.Service.OutDir = t.TempDir()
	plan := call(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"plan_host_scan","arguments":{"host_id":"linux-test-001","profile":"quick"}}}`+"\n")
	rec := decodeTool[app.PlanRecord](t, plan)
	run := call(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_host_scan","arguments":{"plan_id":"`+rec.PlanID+`","idempotency_key":"k1"}}}`+"\n")
	if strings.Contains(run, `"scan_ready": true`) || strings.Contains(run, `"collector_available": true`) || strings.Contains(run, `"execution_ready": true`) {
		t.Fatalf("fixture inspect claimed live scan: %s", run)
	}
	first := decodeTool[map[string]any](t, run)
	job, _ := first["job"].(map[string]any)
	scanID, _ := job["scan_id"].(string)
	if scanID == "" {
		t.Fatalf("missing scan id: %s", run)
	}
	repeat := call(t, srv, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_host_scan","arguments":{"plan_id":"`+rec.PlanID+`","idempotency_key":"k1"}}}`+"\n")
	again := decodeTool[map[string]any](t, repeat)
	repeatJob, _ := again["job"].(map[string]any)
	if repeatJob["scan_id"] != scanID {
		t.Fatalf("idempotency re-executed: %s vs %s", scanID, repeat)
	}
	foreign := testServer(t, "operator-zone-b")
	cross := call(t, foreign, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"plan_host_scan","arguments":{"host_id":"linux-test-001","profile":"quick"}}}`+"\n")
	if !strings.Contains(cross, "HOST_NOT_AUTHORIZED") {
		t.Fatalf("cross-zone plan accepted: %s", cross)
	}
	auditor := testServer(t, "auditor-carol")
	blocked := call(t, auditor, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_host_scan","arguments":{"host_id":"linux-test-001","profile":"quick"}}}`+"\n")
	if !strings.Contains(blocked, "AUTH_DENIED") {
		t.Fatalf("auditor ran a scan: %s", blocked)
	}
}

func testServer(t *testing.T, principal string) *Server {
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
	return &Server{Service: app.New(*inv, dir), Caller: caller}
}

func call(t *testing.T, srv *Server, line string) string {
	t.Helper()
	if !srv.initialized {
		initLine := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"hostsec-test","version":"0"}}}` + "\n"
		_ = callRaw(t, srv, initLine)
	}
	return lastLine(callRaw(t, srv, line))
}

func callRaw(t *testing.T, srv *Server, line string) string {
	t.Helper()
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), strings.NewReader(line), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return lines[len(lines)-1]
}

func decodeTool[T any](t *testing.T, line string) T {
	t.Helper()
	var wrapped struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &wrapped); err != nil {
		t.Fatal(line, err)
	}
	var value T
	if err := json.Unmarshal([]byte(wrapped.Result.Content[0].Text), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
