package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const (
	ModuleServiceInventory     = "service_inventory"
	ModulePersistenceInventory = "persistence_inventory"
)

type Persistence struct {
	Root string
	Now  func() time.Time
	view fileView
}

type serviceInventory struct {
	Units  []unitRecord `json:"units"`
	Source string       `json:"source"`
}

type unitRecord struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	State       string `json:"state"`
	User        string `json:"user"`
	ExecStart   string `json:"exec_start"`
	Description string `json:"description"`
	Owner       string `json:"owner"`
	Mode        string `json:"mode"`
	Source      string `json:"source"`
}

type persistenceInventory struct {
	Timers        []unitRecord `json:"timers"`
	Cron          []cronRecord `json:"cron"`
	AtJobs        []string     `json:"at_jobs"`
	RCLocal       *fileMeta    `json:"rc_local"`
	Profiles      []fileMeta   `json:"profiles"`
	KernelModules []string     `json:"kernel_modules"`
	AtStatus      string       `json:"at_status"`
}

type cronRecord struct {
	Schedule string `json:"schedule"`
	User     string `json:"user"`
	Command  string `json:"command"`
	Source   string `json:"source"`
}

type fileMeta struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

func (p Persistence) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	system := System(p)
	started := system.now().UTC()
	result := collector.Result{
		ModuleID: req.ModuleID, Version: collector.Version,
		StartedAt: started.Format(domain.TimeLayout), Records: []map[string]any{},
		RawRefs: []string{}, Warnings: []string{}, Status: domain.CollectionFailed, Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModuleServiceInventory && req.ModuleID != ModulePersistenceInventory {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "persistence collector implements service_inventory and persistence_inventory"}
	}
	if req.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Limits.Timeout)
		defer cancel()
	}
	if err := validateRoot(p.Root); err != nil {
		result.Warnings = append(result.Warnings, "collector_root_rejected")
		return system.finish(result, started, domain.CollectionNotAvailable, "ROOT_REJECTED"), nil
	}
	view := p.view
	if view == nil {
		opened, err := openView(p.Root, req.Limits.MaxBytes)
		if err != nil {
			result.Warnings = append(result.Warnings, "root_open_failed")
			return system.finish(result, started, domain.CollectionFailed, "ROOT_OPEN_FAILED"), nil
		}
		defer func() { _ = opened.Close() }()
		view = opened
	}
	if req.ModuleID == ModuleServiceInventory {
		return collectServices(ctx, system, view, result, started)
	}
	return collectPersistence(ctx, system, view, result, started)
}

func collectServices(ctx context.Context, system System, view fileView, result collector.Result, started time.Time) (collector.Result, error) {
	units, refs, warnings, err := readUnits(ctx, view)
	result.RawRefs = refs
	result.Warnings = append(result.Warnings, warnings...)
	if isContext(err) {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), nil
	}
	services := make([]unitRecord, 0)
	for _, unit := range units {
		if unit.Kind == "service" {
			services = append(services, unit)
		}
	}
	if len(services) == 0 {
		encoded, _ := toRecordMap(serviceInventory{Units: []unitRecord{}, Source: "none"})
		result.Records = []map[string]any{encoded}
		result.Completeness = domain.CompletenessUnavailable
		return system.finish(result, started, domain.CollectionNotApplicable, "SYSTEMD_NOT_APPLICABLE"), nil
	}
	encoded, encodeErr := toRecordMap(serviceInventory{Units: services, Source: "unit_files"})
	if encodeErr != nil {
		return system.finish(result, started, domain.CollectionFailed, "ENCODE_FAILED"), nil
	}
	result.Records = []map[string]any{encoded}
	if len(warnings) == 0 {
		result.Completeness = domain.CompletenessComplete
		return system.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_SERVICE"), nil
}

func collectPersistence(ctx context.Context, system System, view fileView, result collector.Result, started time.Time) (collector.Result, error) {
	inv, refs, warnings, err := readPersistence(ctx, view)
	result.RawRefs = refs
	result.Warnings = append(result.Warnings, warnings...)
	if isContext(err) {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), nil
	}
	encoded, encodeErr := toRecordMap(inv)
	if encodeErr != nil {
		return system.finish(result, started, domain.CollectionFailed, "ENCODE_FAILED"), nil
	}
	result.Records = []map[string]any{encoded}
	if len(warnings) == 0 {
		result.Completeness = domain.CompletenessComplete
		return system.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_PERSISTENCE"), nil
}

func readUnits(ctx context.Context, view fileView) ([]unitRecord, []string, []string, error) {
	records := make([]unitRecord, 0)
	refs := make([]string, 0)
	warnings := make([]string, 0)
	for _, dir := range []string{"etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"} {
		for _, path := range listDir(view, dir) {
			if err := ctx.Err(); err != nil {
				return records, refs, warnings, err
			}
			if !strings.HasSuffix(path, ".service") && !strings.HasSuffix(path, ".timer") {
				continue
			}
			raw, ref, warn, err := readText(ctx, view, path)
			if isContext(err) {
				return records, refs, warnings, err
			}
			if warn != "" {
				warnings = append(warnings, warn)
			}
			if ref != "" {
				refs = append(refs, ref)
			}
			if raw == "" {
				continue
			}
			records = append(records, parseUnit(view, path, raw))
		}
	}
	return records, compactRefs(refs...), compactRefs(warnings...), nil
}

func parseUnit(view fileView, path, raw string) unitRecord {
	rec := unitRecord{Name: pathBase(path), Source: path, Kind: "service", State: "unit_file"}
	if strings.HasSuffix(path, ".timer") {
		rec.Kind = "timer"
	}
	if info, err := view.Lstat(path); err == nil {
		rec.Mode = info.Mode().String()
		rec.Owner = fileOwner(info)
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ExecStart":
			rec.ExecStart = strings.TrimSpace(value)
		case "User":
			rec.User = strings.TrimSpace(value)
		case "Description":
			rec.Description = strings.TrimSpace(value)
		}
	}
	return rec
}

func readPersistence(ctx context.Context, view fileView) (persistenceInventory, []string, []string, error) {
	inv := persistenceInventory{
		Timers: []unitRecord{}, Cron: []cronRecord{}, AtJobs: []string{},
		Profiles: []fileMeta{}, KernelModules: []string{}, AtStatus: domain.CollectionNotAvailable,
	}
	units, unitRefs, unitWarn, err := readUnits(ctx, view)
	if isContext(err) {
		return inv, nil, nil, err
	}
	for _, unit := range units {
		if unit.Kind == "timer" {
			inv.Timers = append(inv.Timers, unit)
		}
	}
	cron, cronRefs, cronWarn, err := readCron(ctx, view)
	if isContext(err) {
		return inv, nil, nil, err
	}
	inv.Cron = cron
	if entries := listDir(view, "var/spool/cron/atjobs"); len(entries) > 0 {
		inv.AtJobs = entries
		inv.AtStatus = domain.CollectionSuccess
	} else if _, atErr := view.Lstat("var/spool/cron/atjobs"); atErr == nil {
		inv.AtStatus = domain.CollectionSuccess
	}
	rc, rcRef, rcWarn, err := readOptionalMeta(ctx, view, "etc/rc.local")
	if isContext(err) {
		return inv, nil, nil, err
	}
	inv.RCLocal = rc
	profiles := make([]fileMeta, 0)
	refs := append(append([]string{}, unitRefs...), cronRefs...)
	warnings := append(append([]string{}, unitWarn...), cronWarn...)
	if rcRef != "" {
		refs = append(refs, rcRef)
	}
	if rcWarn != "" {
		warnings = append(warnings, rcWarn)
	}
	for _, path := range append([]string{"etc/profile", "etc/bash.bashrc"}, listDir(view, "etc/profile.d")...) {
		meta, ref, warn, metaErr := readOptionalMeta(ctx, view, path)
		if isContext(metaErr) {
			return inv, refs, warnings, metaErr
		}
		if meta != nil {
			profiles = append(profiles, *meta)
		}
		if ref != "" {
			refs = append(refs, ref)
		}
		if warn != "" {
			warnings = append(warnings, warn)
		}
	}
	inv.Profiles = profiles
	modRaw, modRef, modWarn, err := readOptionalText(ctx, view, "proc/modules")
	if isContext(err) {
		return inv, refs, warnings, err
	}
	inv.KernelModules = parseModules(modRaw)
	if modRef != "" {
		refs = append(refs, modRef)
	}
	if modWarn != "" {
		warnings = append(warnings, modWarn)
	}
	return inv, compactRefs(refs...), compactRefs(warnings...), nil
}

func readCron(ctx context.Context, view fileView) ([]cronRecord, []string, []string, error) {
	records := make([]cronRecord, 0)
	refs := make([]string, 0)
	warnings := make([]string, 0)
	paths := append([]string{"etc/crontab"}, listDir(view, "etc/cron.d")...)
	paths = append(paths, listDir(view, "var/spool/cron/crontabs")...)
	for _, path := range paths {
		raw, ref, warn, err := readText(ctx, view, path)
		if isContext(err) {
			return records, refs, warnings, err
		}
		if ref != "" {
			refs = append(refs, ref)
		}
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		userHint := ""
		if strings.Contains(path, "crontabs/") {
			userHint = pathBase(path)
		}
		records = append(records, parseCron(path, raw, userHint)...)
	}
	return records, compactRefs(refs...), compactRefs(warnings...), nil
}

func parseCron(source, raw, userHint string) []cronRecord {
	out := make([]cronRecord, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		rec := cronRecord{Schedule: strings.Join(fields[:5], " "), Source: source, User: userHint, Command: strings.Join(fields[5:], " ")}
		if userHint == "" && len(fields) >= 7 {
			rec.User = fields[5]
			rec.Command = strings.Join(fields[6:], " ")
		}
		out = append(out, rec)
	}
	return out
}

func readOptionalMeta(ctx context.Context, view fileView, path string) (*fileMeta, string, string, error) {
	raw, ref, warn, err := readOptionalText(ctx, view, path)
	if isContext(err) {
		return nil, "", "", err
	}
	if raw == "" {
		return nil, ref, warn, err
	}
	sum := sha256.Sum256([]byte(raw))
	return &fileMeta{Path: path, SHA256: hex.EncodeToString(sum[:]), Size: len(raw)}, ref, warn, nil
}

func readOptionalText(ctx context.Context, view fileView, path string) (string, string, string, error) {
	raw, ref, warn, err := readText(ctx, view, path)
	if isContext(err) {
		return "", "", "", err
	}
	if isMissingWarn(warn) {
		return "", "", "", nil
	}
	return raw, ref, warn, err
}

func isMissingWarn(warn string) bool {
	return strings.HasSuffix(warn, "_missing")
}

func fileOwner(info fs.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(st.Uid), 10)
}

func parseModules(raw string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out = append(out, fields[0])
	}
	return out
}

func pathBase(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
