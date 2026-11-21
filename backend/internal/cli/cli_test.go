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

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

var errWrite = context.Canceled

func TestWriterFailureDoesNotSucceed(t *testing.T) {
	if Run(context.Background(), []string{"version", "--json"}, failWriter{}, ioDiscard{}) == 0 {
		t.Fatal("writer failure reported success")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write([]byte) (int, error) { return 0, nil }

func TestTimeoutAndConcurrencyFlags(t *testing.T) {
	code, out, err := call("plan", "--file", "../../../examples/hosts.yaml", "--host", "linux-test-001", "--dry-run", "--timeout-seconds", "-1")
	if code == 0 || out != "" || !json.Valid([]byte(err)) {
		t.Fatal("negative timeout accepted")
	}
	code, out, err = call("plan", "--file", "../../../examples/hosts.yaml", "--host", "linux-test-001", "--dry-run", "--max-concurrency", "9")
	if code == 0 || out != "" || !json.Valid([]byte(err)) {
		t.Fatal("oversize concurrency accepted")
	}
	code, out, err = call("plan", "--file", "../../../examples/hosts.yaml", "--host", "linux-test-001", "--dry-run", "--timeout-seconds", "30", "--json")
	if code != 0 || err != "" || !json.Valid([]byte(out)) {
		t.Fatalf("valid timeout rejected %d %s %s", code, out, err)
	}
}

func TestCancelDuringParseHook(t *testing.T) {
	orig := afterParse
	afterParse = func(ctx context.Context) {
		if cancel, ok := ctx.Value("unused").(context.CancelFunc); ok {
			cancel()
		}
	}
	defer func() { afterParse = orig }()
	ctx, cancel := context.WithCancel(context.Background())
	afterParse = func(context.Context) { cancel() }
	var out, err bytes.Buffer
	if Run(ctx, []string{"assets", "validate", "--file", "../../../examples/hosts.yaml"}, &out, &err) == 0 {
		t.Fatal("ignored mid-command cancel")
	}
}

func TestAssetsSnapshotAndIntent(t *testing.T) {
	code, out, err := call("assets", "snapshot", "--file", "../../../examples/hosts.yaml", "--json")
	if code != 0 || err != "" || !strings.Contains(out, "content_hash") {
		t.Fatalf("snapshot failed %d %s %s", code, out, err)
	}
	code, out, err = call("intent", "--file", "../../../examples/hosts.yaml", "--host", "linux-test-001", "--profile", "quick", "--requester", "operator-alice", "--valid-from", "2026-11-20T00:00:00Z", "--valid-until", "2026-11-20T04:00:00Z")
	if code != 0 || err != "" || !strings.Contains(out, "intent_hash") || strings.Contains(out, `"execution_ready": true`) {
		t.Fatalf("intent failed %d %s %s", code, out, err)
	}
}

func TestInspectFixtureCLI(t *testing.T) {
	code, out, err := call("inspect-fixture", "--file", "../../../examples/hosts.yaml", "--host", "linux-test-001", "--root", "/", "--out", t.TempDir())
	if code == 0 || out != "" || !json.Valid([]byte(err)) {
		t.Fatalf("live root accepted %d %s %s", code, out, err)
	}
}

func TestValidVersion(t *testing.T) {
	if !ValidVersion("0.1.0-dev") || !ValidVersion("1.2.3") || ValidVersion("") || ValidVersion("latest") {
		t.Fatal("version validation mismatch")
	}
}
