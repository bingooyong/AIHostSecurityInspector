package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func call(args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := Run(context.Background(), args, &out, &err)
	return code, out.String(), err.String()
}
func TestCLIJSONAndHelp(t *testing.T) {
	for _, args := range [][]string{{"version", "--json"}, {"assets", "validate", "--file", "../../../examples/hosts.yaml", "--json"}, {"assets", "list", "--file", "../../../examples/hosts.yaml", "--json"}, {"plan", "--file", "../../../examples/hosts.yaml", "--targets", "group:pilot", "--dry-run", "--json"}} {
		code, out, err := call(args...)
		if code != 0 || err != "" || !json.Valid([]byte(out)) {
			t.Fatalf("command failed: %v %d %s %s", args, code, out, err)
		}
	}
	code, out, _ := call("--help")
	if code != 0 || !strings.Contains(out, "offline") {
		t.Fatal("missing help")
	}
	code, out, err := call("doctor", "--json")
	if code == 0 || !json.Valid([]byte(out)) || !strings.Contains(out, `"collector_available": false`) || !json.Valid([]byte(err)) {
		t.Fatal("doctor falsely ready")
	}
}
func TestCLIRejectsInjectionAndUnsupportedSurface(t *testing.T) {
	tests := [][]string{{"scan"}, {"mcp", "serve"}, {"version", "--exec", "CANARY_SECRET"}, {"version", "extra"}, {"plan", "--file", "../../../examples/hosts.yaml", "--host", "linux-test-001", "--targets", "group:pilot", "--dry-run"}, {"plan", "--file", "../../../examples/hosts.yaml", "--host", "linux-test-001"}, {"plan", "--file", "../../../examples/hosts.yaml", "--targets", "group:mixed", "--dry-run"}, {"assets", "validate", "--file", "CANARY_SECRET"}, {"assets", "validate", "--command", "CANARY_SECRET"}}
	for _, args := range tests {
		code, out, err := call(args...)
		if code == 0 || out != "" || !json.Valid([]byte(err)) || strings.Contains(err, "CANARY_SECRET") {
			t.Fatalf("unsafe response %v %d %q %q", args, code, out, err)
		}
	}
}
func TestCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, err bytes.Buffer
	if Run(ctx, []string{"version"}, &out, &err) == 0 || out.Len() != 0 {
		t.Fatal("ignored cancellation")
	}
}
