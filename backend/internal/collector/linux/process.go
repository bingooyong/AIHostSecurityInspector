package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const ModuleProcessInventory = "process_inventory"

type Process struct {
	Root string
	Now  func() time.Time
	view fileView
	Live bool
}

type processRecord struct {
	PID          int    `json:"pid"`
	PPID         int    `json:"ppid"`
	UID          int    `json:"uid"`
	Name         string `json:"name"`
	State        string `json:"state"`
	ExePath      string `json:"exe_path"`
	ExeExists    bool   `json:"exe_exists"`
	ExeReason    string `json:"exe_reason"`
	ExeSHA256    string `json:"exe_sha256,omitempty"`
	StartTicks   int64  `json:"start_ticks"`
	ArgvSummary  string `json:"argv_summary"`
	KernelThread bool   `json:"kernel_thread"`
}

func (p Process) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	system := System(p)
	started := system.now().UTC()
	result := collector.Result{
		ModuleID:     ModuleProcessInventory,
		Version:      collector.Version,
		StartedAt:    started.Format(domain.TimeLayout),
		Records:      []map[string]any{},
		RawRefs:      []string{},
		Warnings:     []string{},
		Status:       domain.CollectionFailed,
		Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModuleProcessInventory {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "process collector only implements process_inventory"}
	}
	if req.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Limits.Timeout)
		defer cancel()
	}
	if err := validateRootMode(p.Root, p.Live); err != nil {
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
	records, refs, warnings, err := p.readProcesses(ctx, view, req.Limits.MaxRecords)
	result.RawRefs = refs
	result.Warnings = append(result.Warnings, warnings...)
	if isContext(err) {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), nil
	}
	for _, record := range records {
		encoded, encodeErr := processMap(record)
		if encodeErr != nil {
			continue
		}
		result.Records = append(result.Records, encoded)
	}
	if len(result.Records) == 0 {
		result.Completeness = domain.CompletenessUnavailable
		return system.finish(result, started, domain.CollectionFailed, "NO_PROCESS_RECORDS"), nil
	}
	if len(warnings) == 0 {
		result.Completeness = domain.CompletenessComplete
		return system.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_PROCESS"), nil
}

func (p *Process) readProcesses(ctx context.Context, view fileView, maxRecords int) ([]processRecord, []string, []string, error) {
	entries, err := listProcPIDs(view)
	if err != nil {
		if isContext(err) {
			return nil, nil, nil, err
		}
		return nil, nil, []string{"proc_unreadable"}, err
	}
	if maxRecords <= 0 {
		maxRecords = 4096
	}
	records := make([]processRecord, 0, len(entries))
	refs := make([]string, 0)
	warnings := make([]string, 0)
	for _, pid := range entries {
		if err := ctx.Err(); err != nil {
			return records, refs, warnings, err
		}
		if len(records) >= maxRecords {
			warnings = append(warnings, "process_record_limit")
			break
		}
		record, recRefs, recWarn, recErr := readOneProcess(ctx, view, pid)
		refs = append(refs, recRefs...)
		warnings = append(warnings, recWarn...)
		if recErr != nil {
			if isContext(recErr) {
				return records, refs, warnings, recErr
			}
			continue
		}
		records = append(records, record)
	}
	return records, compactRefs(refs...), compactRefs(warnings...), nil
}

func listProcPIDs(view fileView) ([]int, error) {
	entries, err := view.ReadDir("proc")
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func readOneProcess(ctx context.Context, view fileView, pid int) (processRecord, []string, []string, error) {
	base := "proc/" + strconv.Itoa(pid)
	statRaw, statRef, statWarn, err := readText(ctx, view, base+"/stat")
	if err != nil {
		return processRecord{}, nil, compactRefs(statWarn, base+"_stat_unreadable"), err
	}
	name, state, ppid, startTicks, parseErr := parseProcStat(statRaw)
	if parseErr != nil {
		return processRecord{}, []string{statRef}, []string{base + "_stat_invalid"}, parseErr
	}
	statusRaw, statusRef, statusWarn, _ := readText(ctx, view, base+"/status")
	uid := parseUID(statusRaw)
	cmdline, cmdRef, cmdWarn, _ := readText(ctx, view, base+"/cmdline")
	exePath, exists, reason, hash, exeWarn := classifyExe(view, base, name)
	refs := compactRefs(statRef, statusRef, cmdRef, base+"/exe")
	warnings := compactRefs(statWarn, statusWarn, cmdWarn, exeWarn)
	return processRecord{
		PID:          pid,
		PPID:         ppid,
		UID:          uid,
		Name:         name,
		State:        state,
		ExePath:      exePath,
		ExeExists:    exists,
		ExeReason:    reason,
		ExeSHA256:    hash,
		StartTicks:   startTicks,
		ArgvSummary:  summarizeArgv(cmdline),
		KernelThread: reason == "kernel_thread",
	}, refs, warnings, nil
}

func parseProcStat(raw string) (name, state string, ppid int, startTicks int64, err error) {
	start := strings.Index(raw, "(")
	end := strings.LastIndex(raw, ")")
	if start < 0 || end <= start {
		return "", "", 0, 0, errors.New("stat comm is invalid")
	}
	name = raw[start+1 : end]
	fields := strings.Fields(raw[end+1:])
	if len(fields) < 20 {
		return "", "", 0, 0, errors.New("stat fields are incomplete")
	}
	state = fields[0]
	ppid, _ = strconv.Atoi(fields[1])
	startTicks, _ = strconv.ParseInt(fields[19], 10, 64)
	return name, state, ppid, startTicks, nil
}

func parseUID(raw string) int {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ := strconv.Atoi(fields[1])
				return uid
			}
		}
	}
	return -1
}

func classifyExe(view fileView, base, name string) (path string, exists bool, reason, hash, warning string) {
	link, err := view.Readlink(base + "/exe")
	if isPermission(err) {
		return "", false, "permission_denied", "", base + "/exe_permission_denied"
	}
	if isNotExist(err) {
		if looksKernel(name, view, base) {
			return "", false, "kernel_thread", "", ""
		}
		return "", false, "exe_missing", "", ""
	}
	if err != nil {
		return "", false, "read_failed", "", base + "/exe_unreadable"
	}
	if strings.Contains(link, " (deleted)") {
		return strings.TrimSuffix(link, " (deleted)"), false, "deleted", "", ""
	}
	payload, readErr := view.ReadFile(strings.TrimPrefix(link, "/"))
	if isPermission(readErr) {
		return link, false, "permission_denied", "", base + "/exe_permission_denied"
	}
	if isNotExist(readErr) {
		return link, false, "exe_missing", "", ""
	}
	if readErr != nil && !errors.Is(readErr, errTruncated) {
		return link, false, "read_failed", "", base + "/exe_unreadable"
	}
	sum := sha256.Sum256(payload)
	warning = ""
	if errors.Is(readErr, errTruncated) {
		warning = base + "/exe_truncated"
	}
	return link, true, "exe_exists", hex.EncodeToString(sum[:]), warning
}

func looksKernel(name string, view fileView, base string) bool {
	data, err := view.ReadFile(base + "/cmdline")
	if err != nil && isNotExist(err) {
		return true
	}
	return err == nil && len(data) == 0 && !strings.Contains(name, "/")
}

func summarizeArgv(raw string) string {
	parts := strings.Split(strings.TrimRight(raw, "\x00"), "\x00")
	summary := strings.Join(parts, " ")
	if len(summary) > 256 {
		return summary[:256]
	}
	return summary
}

func processMap(record processRecord) (map[string]any, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}
