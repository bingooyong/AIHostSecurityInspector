package domain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalExecutionIntentStableAcrossSliceOrder(t *testing.T) {
	a := validIntent()
	b := validIntent()
	b.HostIDs = []string{"linux-test-001"}
	b.Modules = []string{"process_inventory", "host_identity"}
	b.ExcludedPaths = []string{"/sys", "/proc"}
	ha, err := HashExecutionIntent(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := HashExecutionIntent(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("canonical hash changed with list order: %s vs %s", ha, hb)
	}
	canonical, err := CanonicalExecutionIntent(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(canonical, []byte(IntentCanonicalVersion+"\n")) {
		t.Fatal("missing canonical version prefix")
	}
	goldenPath := filepath.Join("testdata", "execution-intent.sha256")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		if writeErr := os.WriteFile(goldenPath, []byte(ha+"\n"), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		t.Fatalf("wrote intent hash golden %s; re-run tests", ha)
	}
	if got, want := ha, string(bytes.TrimSpace(golden)); got != want {
		t.Fatalf("intent hash drifted: got %s want %s", got, want)
	}
}

func TestHashExecutionIntentSensitiveFields(t *testing.T) {
	base, err := HashExecutionIntent(validIntent())
	if err != nil {
		t.Fatal(err)
	}
	type mutate func(*ExecutionIntent)
	cases := map[string]mutate{
		"host": func(in *ExecutionIntent) {
			in.HostIDs = []string{"linux-test-002"}
			in.IdentityRefs = []string{"identity-linux-test-002"}
		},
		"profile": func(in *ExecutionIntent) {
			in.Profile = ProfileStandard
			in.Modules = append(in.Modules, "package_inventory")
		},
		"policy":    func(in *ExecutionIntent) { in.PolicyHash = sampleHash()[:63] + "c" },
		"asset":     func(in *ExecutionIntent) { in.AssetSnapshotHash = sampleHashB() },
		"window":    func(in *ExecutionIntent) { in.ValidUntil = "2026-11-20T05:00:00Z" },
		"paths":     func(in *ExecutionIntent) { in.ExcludedPaths = []string{"/proc", "/var/backups"} },
		"limits":    func(in *ExecutionIntent) { in.Limits.MaxFiles = 9999 },
		"mode":      func(in *ExecutionIntent) { in.Mode = "WRITE" },
		"requester": func(in *ExecutionIntent) { in.RequesterPrincipal = "operator-bob" },
	}
	for name, fn := range cases {
		in := validIntent()
		fn(&in)
		got, err := HashExecutionIntent(in)
		if name == "mode" {
			if err == nil {
				t.Fatalf("%s: expected rejection of non-read-only mode", name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == base {
			t.Fatalf("%s: hash did not change", name)
		}
	}
}

func TestExecutionIntentRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ExecutionIntent)
		code string
	}{
		{"schema", func(in *ExecutionIntent) { in.SchemaVersion = "2.0" }, CodeSchemaVersionUnsupported},
		{"ip-host", func(in *ExecutionIntent) { in.HostIDs = []string{"192.0.2.10"} }, CodeInvalidID},
		{"empty-modules", func(in *ExecutionIntent) { in.Modules = nil }, CodeInvalidID},
		{"root-path", func(in *ExecutionIntent) { in.AllowedPaths = []string{"/"} }, CodeInvalidCanonical},
		{"pressure", func(in *ExecutionIntent) { in.Limits.StopOnResourcePressure = false }, CodeInvalidCanonical},
		{"inverted", func(in *ExecutionIntent) {
			in.ValidFrom = "2026-11-21T00:00:00Z"
			in.ValidUntil = "2026-11-20T00:00:00Z"
		}, CodeInvalidTimestamp},
		{"deep-no-window", func(in *ExecutionIntent) { in.Profile = ProfileDeep; in.Limits.MaintenanceWindowRequired = true }, CodeInvalidCanonical},
	}
	for _, tc := range cases {
		in := validIntent()
		tc.mut(&in)
		err := in.Validate()
		if err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		de, ok := err.(*Error)
		if !ok || de.Code != tc.code {
			t.Fatalf("%s: got %v want %s", tc.name, err, tc.code)
		}
	}
}

func TestDeepIntentRequiresWindow(t *testing.T) {
	in := validIntent()
	in.Profile = ProfileDeep
	in.Limits.MaintenanceWindowRequired = true
	in.MaintenanceWindow = &MaintenanceWindow{Timezone: "UTC", Start: "2026-11-20T00:00:00Z", End: "2026-11-20T02:00:00Z"}
	if _, err := HashExecutionIntent(in); err != nil {
		t.Fatal(err)
	}
	in.MaintenanceWindow.Timezone = "Not/AZone"
	if err := in.Validate(); err == nil {
		t.Fatal("invalid timezone accepted")
	}
}

func TestCanonicalJSONHasNoFloatLimits(t *testing.T) {
	canonical, err := CanonicalExecutionIntent(validIntent())
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.SplitN(canonical, []byte("\n"), 2)[1]
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatal(err)
	}
	limits := parsed["limits"].(map[string]any)
	for _, key := range []string{"timeout_seconds", "max_concurrency", "max_files"} {
		switch limits[key].(type) {
		case float64:
			// encoding/json numbers are float64; canonical bytes must still be integers without a decimal.
		default:
			t.Fatalf("%s: unexpected JSON type", key)
		}
	}
	if bytes.Contains(payload, []byte("timeout_seconds\":900.0")) {
		t.Fatal("canonical encoding used a float")
	}
}
