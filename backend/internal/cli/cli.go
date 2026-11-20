// Package cli is the command boundary for the offline HostSec slice.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
)

var Version = "0.1.0-dev"

const help = `HostSec — authorized offline host inspection planning
Usage:
  hostsec version [--json]
  hostsec doctor [--json]
  hostsec assets validate --file PATH [--json]
  hostsec assets list --file PATH [--json]
  hostsec plan --file PATH (--host ID | --targets group:NAME) --profile quick --dry-run [--json]

Profiles: quick, standard, deep, incident-response.
This release only creates offline plans. Scanning and AI are not implemented.
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
			return 1
		}
		return 0
	}
	command := args[0]
	rest := args[1:]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "machine-readable JSON")
	var file, host, targets, profile string
	var dryRun bool
	action := ""
	switch command {
	case "version", "doctor":
	case "assets":
		if len(rest) == 0 {
			return fail(stderr, "INVALID_ARGUMENT", "assets action is required", 2)
		}
		action = rest[0]
		rest = rest[1:]
		if action != "validate" && action != "list" {
			return fail(stderr, "INVALID_ARGUMENT", "unsupported assets action", 2)
		}
		fs.StringVar(&file, "file", "", "asset inventory file")
	case "plan":
		fs.StringVar(&file, "file", "", "asset inventory file")
		fs.StringVar(&host, "host", "", "registered host ID")
		fs.StringVar(&targets, "targets", "", "registered group selector")
		fs.StringVar(&profile, "profile", "quick", "scan profile")
		fs.BoolVar(&dryRun, "dry-run", false, "required: offline plan only")
	default:
		return fail(stderr, "INVALID_ARGUMENT", "unsupported command", 2)
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, e := io.WriteString(stdout, help); e != nil {
				return 1
			}
			return 0
		}
		return fail(stderr, "INVALID_ARGUMENT", "invalid command arguments", 2)
	}
	if fs.NArg() != 0 {
		return fail(stderr, "INVALID_ARGUMENT", "unexpected positional arguments", 2)
	}
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
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fail(stderr, "CANCELLED", "operation cancelled", 1)
		}
		return fail(stderr, "INVALID_ASSETS", "asset inventory could not be loaded or validated", 2)
	}
	if command == "assets" {
		if action == "list" {
			view := inv.Authorized()
			return output(stdout, stderr, true, view, "")
		}
		result := map[string]any{"valid": true, "version": inv.Version, "host_count": len(inv.Hosts), "group_count": len(inv.Groups)}
		return output(stdout, stderr, *jsonOut, result, "Asset inventory valid.")
	}
	plan, err := planner.Build(ctx, *inv, planner.Request{HostID: host, Targets: targets, Profile: profile, DryRun: dryRun})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fail(stderr, "CANCELLED", "operation cancelled", 1)
		}
		return fail(stderr, "PLAN_REJECTED", "plan target, authorization, profile, or dry-run requirement rejected", 2)
	}
	if *jsonOut {
		return output(stdout, stderr, true, plan, "")
	}
	// A plan is structured even without --json, so its scope is never hidden in a summary.
	return output(stdout, stderr, true, plan, "")
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
