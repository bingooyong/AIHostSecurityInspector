package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/orchestrator"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
)

var Version = "0.1.0-dev"

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[A-Za-z0-9.-]+)?$`)

func ValidVersion(v string) bool { return versionPattern.MatchString(v) }

var afterParse = func(context.Context) {}

const help = `HostSec — authorized offline host inspection planning
Usage:
  hostsec version [--json]
  hostsec doctor [--json]
  hostsec assets validate --file PATH [--json]
  hostsec assets list --file PATH [--json]
  hostsec assets snapshot --file PATH [--json]
  hostsec assets diff --file PATH --against PATH [--json]
  hostsec plan --file PATH (--host ID | --targets group:NAME) --profile quick --dry-run [--json]
  hostsec intent --file PATH (--host ID | --targets group:NAME) --profile NAME --requester ID --valid-from RFC3339 --valid-until RFC3339 [--json]
  hostsec preflight --file PATH --intent-file PATH [--approval PATH] [--trust-store PATH] [--json]
  hostsec inspect-fixture --file PATH --host ID --root ABS_PATH --out DIR --profile quick|standard [--json]

Profiles: quick, standard, deep, incident-response.
This release plans and verifies approvals offline. hostsec scan remains unsupported.
inspect-fixture reads a synthetic rooted fixture only; it does not set collector_available or scan_ready.
`

type diagnostic struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
type DoctorResult struct {
	SchemaVersion            string   `json:"schema_version"`
	Version                  string   `json:"version"`
	OS                       string   `json:"os"`
	Architecture             string   `json:"architecture"`
	OfflinePlanningAvailable bool     `json:"offline_planning_available"`
	LinuxPlatformSupported   bool     `json:"linux_platform_supported"`
	CollectorAvailable       bool     `json:"collector_available"`
	ScanReady                bool     `json:"scan_ready"`
	Limitations              []string `json:"limitations"`
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		return fail(stderr, "CANCELLED", "operation cancelled", 1)
	}
	if len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")) {
		if _, err := io.WriteString(stdout, help); err != nil {
			return fail(stderr, "OUTPUT_FAILED", "cannot write command result", 1)
		}
		return 0
	}
	command := args[0]
	rest := args[1:]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "machine-readable JSON")
	var file, host, targets, profile, against, requester, validFrom, validUntil, windowStart, windowEnd, timezone, intentFile, approvalFile, trustStore, inspectRoot, outDir string
	var dryRun bool
	var timeoutSeconds, maxConcurrency int
	action := ""
	switch command {
	case "version", "doctor":
	case "assets":
		if len(rest) == 0 {
			return fail(stderr, "INVALID_ARGUMENT", "assets action is required", 2)
		}
		action = rest[0]
		rest = rest[1:]
		if action != "validate" && action != "list" && action != "snapshot" && action != "diff" {
			return fail(stderr, "INVALID_ARGUMENT", "unsupported assets action", 2)
		}
		fs.StringVar(&file, "file", "", "asset inventory file")
		if action == "diff" {
			fs.StringVar(&against, "against", "", "previous asset inventory file")
		}
		fs.IntVar(&timeoutSeconds, "timeout-seconds", 0, "optional command deadline")
	case "plan":
		fs.StringVar(&file, "file", "", "asset inventory file")
		fs.StringVar(&host, "host", "", "registered host ID")
		fs.StringVar(&targets, "targets", "", "registered group selector")
		fs.StringVar(&profile, "profile", "quick", "scan profile")
		fs.BoolVar(&dryRun, "dry-run", false, "required: offline plan only")
		fs.IntVar(&timeoutSeconds, "timeout-seconds", 0, "optional command deadline")
		fs.IntVar(&maxConcurrency, "max-concurrency", 0, "optional tighter concurrency bound")
	case "intent":
		fs.StringVar(&file, "file", "", "asset inventory file")
		fs.StringVar(&host, "host", "", "registered host ID")
		fs.StringVar(&targets, "targets", "", "registered group selector")
		fs.StringVar(&profile, "profile", "quick", "scan profile")
		fs.StringVar(&requester, "requester", "", "trusted requester principal")
		fs.StringVar(&validFrom, "valid-from", "", "RFC3339 UTC start")
		fs.StringVar(&validUntil, "valid-until", "", "RFC3339 UTC end")
		fs.StringVar(&windowStart, "window-start", "", "RFC3339 UTC maintenance start")
		fs.StringVar(&windowEnd, "window-end", "", "RFC3339 UTC maintenance end")
		fs.StringVar(&timezone, "timezone", "UTC", "maintenance window timezone")
		fs.IntVar(&timeoutSeconds, "timeout-seconds", 0, "optional command deadline")
	case "preflight":
		fs.StringVar(&file, "file", "", "asset inventory file")
		fs.StringVar(&intentFile, "intent-file", "", "execution intent JSON")
		fs.StringVar(&approvalFile, "approval", "", "signed approval JSON")
		fs.StringVar(&trustStore, "trust-store", "", "trusted principal store JSON")
		fs.IntVar(&timeoutSeconds, "timeout-seconds", 0, "optional command deadline")
	case "inspect-fixture":
		fs.StringVar(&file, "file", "", "asset inventory file")
		fs.StringVar(&host, "host", "", "registered host ID")
		fs.StringVar(&profile, "profile", "quick", "scan profile")
		fs.StringVar(&inspectRoot, "root", "", "absolute synthetic fixture root")
		fs.StringVar(&outDir, "out", "", "absolute output directory")
		fs.IntVar(&timeoutSeconds, "timeout-seconds", 0, "optional command deadline")
	default:
		return fail(stderr, "INVALID_ARGUMENT", "unsupported command", 2)
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, e := io.WriteString(stdout, help); e != nil {
				return fail(stderr, "OUTPUT_FAILED", "cannot write command result", 1)
			}
			return 0
		}
		return fail(stderr, "INVALID_ARGUMENT", "invalid command arguments", 2)
	}
	if fs.NArg() != 0 {
		return fail(stderr, "INVALID_ARGUMENT", "unexpected positional arguments", 2)
	}
	if timeoutSeconds < 0 || timeoutSeconds > 1800 {
		return fail(stderr, "INVALID_ARGUMENT", "timeout-seconds is out of range", 2)
	}
	if maxConcurrency < 0 || maxConcurrency > 2 {
		return fail(stderr, "INVALID_ARGUMENT", "max-concurrency is out of range", 2)
	}
	if timeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	}
	afterParse(ctx)
	if err := ctx.Err(); err != nil {
		return fail(stderr, "CANCELLED", "operation cancelled", 1)
	}
	switch command {
	case "version":
		return output(stdout, stderr, *jsonOut, map[string]string{"version": Version, "go_version": runtime.Version()}, Version)
	case "doctor":
		result := DoctorResult{SchemaVersion: "1.0", Version: Version, OS: runtime.GOOS, Architecture: runtime.GOARCH, OfflinePlanningAvailable: true, LinuxPlatformSupported: runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"), CollectorAvailable: false, ScanReady: false, Limitations: []string{"Collector and scan execution are not implemented; only offline planning is available.", "No target, credential store, scanner, database, or model endpoint was accessed."}}
		if code := output(stdout, stderr, *jsonOut, result, "Offline planning available. Collector unavailable; scan_ready=false."); code != 0 {
			return code
		}
		return fail(stderr, "COLLECTOR_UNAVAILABLE", "Linux collector is not available in this release", 1)
	}
	if file == "" {
		return fail(stderr, "INVALID_ARGUMENT", "asset file is required", 2)
	}
	inv, err := asset.Load(ctx, file)
	if err != nil {
		return assetFail(stderr, err)
	}
	if command == "assets" {
		return runAssets(ctx, stdout, stderr, *jsonOut, action, against, inv)
	}
	if command == "preflight" {
		return runPreflight(ctx, stdout, stderr, *jsonOut, *inv, intentFile, approvalFile, trustStore)
	}
	if command == "intent" {
		return runIntent(ctx, stdout, stderr, *jsonOut, *inv, host, targets, profile, requester, validFrom, validUntil, timezone, windowStart, windowEnd)
	}
	if command == "inspect-fixture" {
		return runInspectFixture(ctx, stdout, stderr, *jsonOut, *inv, host, profile, inspectRoot, outDir)
	}
	plan, err := planner.Build(ctx, *inv, planner.Request{HostID: host, Targets: targets, Profile: profile, DryRun: dryRun})
	if err != nil {
		return planFail(stderr, err)
	}
	if maxConcurrency > 0 && maxConcurrency > plan.Limits.MaxConcurrency {
		return fail(stderr, "PLAN_REJECTED", "max-concurrency cannot exceed the profile bound", 2)
	}
	return output(stdout, stderr, true, plan, "")
}

func runAssets(ctx context.Context, stdout, stderr io.Writer, jsonOut bool, action, against string, inv *asset.Inventory) int {
	switch action {
	case "list":
		return output(stdout, stderr, true, inv.Authorized(), "")
	case "snapshot":
		snap, err := asset.MakeSnapshot(*inv)
		if err != nil {
			return fail(stderr, "INVALID_ASSETS", "asset snapshot could not be created", 2)
		}
		return output(stdout, stderr, true, snap, "")
	case "diff":
		if against == "" {
			return fail(stderr, "INVALID_ARGUMENT", "against inventory is required", 2)
		}
		previous, err := asset.Load(ctx, against)
		if err != nil {
			return assetFail(stderr, err)
		}
		diff, err := asset.DiffInventories(*previous, *inv)
		if err != nil {
			return fail(stderr, "INVALID_ASSETS", "asset inventories could not be compared", 2)
		}
		return output(stdout, stderr, true, diff, "")
	default:
		result := map[string]any{"valid": true, "version": inv.Version, "host_count": len(inv.Hosts), "group_count": len(inv.Groups)}
		return output(stdout, stderr, jsonOut, result, "Asset inventory valid.")
	}
}

func runInspectFixture(ctx context.Context, stdout, stderr io.Writer, _ bool, inv asset.Inventory, host, profile, root, outDir string) int {
	if host == "" || root == "" || outDir == "" {
		return fail(stderr, "INVALID_ARGUMENT", "inspect-fixture requires --host, --root and --out", 2)
	}
	result, err := orchestrator.InspectFixture(ctx, orchestrator.Request{Root: root, Inventory: inv, HostID: host, Profile: profile, OutDir: outDir})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fail(stderr, "CANCELLED", "operation cancelled", 1)
		}
		return fail(stderr, "INSPECT_REJECTED", "fixture inspect was rejected or failed", 2)
	}
	if result.CollectorAvailable || result.ScanReady || result.ExecutionReady {
		return fail(stderr, "INSPECT_REJECTED", "fixture inspect must not mark scan ready", 1)
	}
	return output(stdout, stderr, true, result, "")
}

func runIntent(ctx context.Context, stdout, stderr io.Writer, jsonOut bool, inv asset.Inventory, host, targets, profile, requester, validFrom, validUntil, timezone, windowStart, windowEnd string) int {
	req := planner.IntentRequest{HostID: host, Targets: targets, Profile: profile, RequesterPrincipal: requester, ValidFrom: validFrom, ValidUntil: validUntil}
	if windowStart != "" || windowEnd != "" {
		req.Window = &domain.MaintenanceWindow{Timezone: timezone, Start: windowStart, End: windowEnd}
	}
	intent, err := planner.BuildIntent(ctx, inv, req)
	if err != nil {
		return planFail(stderr, err)
	}
	hash, err := domain.HashExecutionIntent(intent)
	if err != nil {
		return fail(stderr, "PLAN_REJECTED", "execution intent could not be hashed", 2)
	}
	return output(stdout, stderr, true, map[string]any{"intent": intent, "intent_hash": hash}, "")
}

func runPreflight(ctx context.Context, stdout, stderr io.Writer, jsonOut bool, inv asset.Inventory, intentFile, approvalFile, trustStore string) int {
	if intentFile == "" {
		return fail(stderr, "INVALID_ARGUMENT", "intent file is required", 2)
	}
	intent, err := loadIntent(intentFile)
	if err != nil {
		return fail(stderr, "INVALID_ARGUMENT", "execution intent could not be loaded", 2)
	}
	var store approval.TrustStore
	if trustStore != "" {
		store, err = approval.LoadTrustStore(trustStore)
		if err != nil {
			return fail(stderr, "INVALID_ARGUMENT", "trust store could not be loaded", 2)
		}
	}
	var doc *approval.Document
	if approvalFile != "" {
		doc, err = approval.LoadDocument(approvalFile)
		if err != nil {
			return fail(stderr, "INVALID_ARGUMENT", "approval document could not be loaded", 2)
		}
	}
	result, err := planner.Preflight(ctx, inv, intent, store, doc, time.Now, nil, false)
	if err != nil {
		_ = output(stdout, stderr, true, result, "")
		return fail(stderr, "PREFLIGHT_REJECTED", "preflight rejected the execution intent", 2)
	}
	return output(stdout, stderr, true, result, "")
}

func loadIntent(path string) (domain.ExecutionIntent, error) {
	raw, err := approval.ReadBoundedFile(path, 1<<20)
	if err != nil {
		return domain.ExecutionIntent{}, err
	}
	var env struct {
		Intent     *domain.ExecutionIntent `json:"intent"`
		IntentHash string                  `json:"intent_hash"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return domain.ExecutionIntent{}, err
	}
	if env.Intent != nil {
		return *env.Intent, nil
	}
	var intent domain.ExecutionIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		return domain.ExecutionIntent{}, err
	}
	return intent, nil
}

func assetFail(stderr io.Writer, err error) int {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fail(stderr, "CANCELLED", "operation cancelled", 1)
	}
	return fail(stderr, "INVALID_ASSETS", "asset inventory could not be loaded or validated", 2)
}

func planFail(stderr io.Writer, err error) int {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fail(stderr, "CANCELLED", "operation cancelled", 1)
	}
	return fail(stderr, "PLAN_REJECTED", "plan target, authorization, profile, or dry-run requirement rejected", 2)
}

func fail(w io.Writer, code, message string, exit int) int {
	_ = json.NewEncoder(w).Encode(diagnostic{Level: "error", Code: code, Message: message})
	return exit
}

func output(stdout, stderr io.Writer, jsonOut bool, value any, plain string) int {
	var err error
	if jsonOut {
		e := json.NewEncoder(stdout)
		e.SetIndent("", "  ")
		err = e.Encode(value)
	} else {
		_, err = fmt.Fprintln(stdout, plain)
	}
	if err != nil {
		return fail(stderr, "OUTPUT_FAILED", "cannot write command result", 1)
	}
	return 0
}
