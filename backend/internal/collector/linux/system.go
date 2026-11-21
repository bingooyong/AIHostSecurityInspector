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

const (
	ModuleHostIdentity       = "host_identity"
	digestPrefix             = "hostsec:v1:"
	identityCanonicalVersion = "host-identity-canonical-v1"
)

// System reads a rooted Linux view for distribution, kernel, resources, boot
// and a stable hashed identity. It never defaults to the live "/".
type System struct {
	Root string
	Now  func() time.Time
	view fileView
}

type identityRecord struct {
	OS                  string       `json:"os"`
	Distribution        string       `json:"distribution"`
	OSVersion           string       `json:"os_version"`
	VersionCodename     string       `json:"version_codename"`
	Kernel              string       `json:"kernel"`
	KernelBuild         string       `json:"kernel_build"`
	Architecture        string       `json:"architecture"`
	Hostname            string       `json:"hostname"`
	BootTime            string       `json:"boot_time"`
	CPUCount            int          `json:"cpu_count"`
	CPUModel            string       `json:"cpu_model"`
	MemoryKB            int64        `json:"memory_kb"`
	Disks               []diskRecord `json:"disks"`
	MachineIDDigest     string       `json:"machine_id_digest"`
	BootIDDigest        string       `json:"boot_id_digest"`
	IdentityFingerprint string       `json:"identity_fingerprint"`
	View                string       `json:"view"`
	ContainerSignals    []string     `json:"container_signals"`
	UnknownFields       []string     `json:"unknown_fields"`
}

type diskRecord struct {
	Name   string `json:"name"`
	Blocks int64  `json:"blocks"`
}

type identityCanonical struct {
	Architecture    string `json:"architecture"`
	BootIDDigest    string `json:"boot_id_digest"`
	Kernel          string `json:"kernel"`
	MachineIDDigest string `json:"machine_id_digest"`
	OS              string `json:"os"`
	OSVersion       string `json:"os_version"`
}

func (s System) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	started := s.now().UTC()
	result := collector.Result{
		ModuleID:     ModuleHostIdentity,
		Version:      collector.Version,
		StartedAt:    started.Format(domain.TimeLayout),
		Records:      []map[string]any{},
		RawRefs:      []string{},
		Warnings:     []string{},
		Status:       domain.CollectionFailed,
		Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return s.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return s.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModuleHostIdentity {
		return s.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "system collector only implements host_identity"}
	}
	if req.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Limits.Timeout)
		defer cancel()
	}
	if err := validateRoot(s.Root); err != nil {
		result.Warnings = append(result.Warnings, "collector_root_rejected")
		return s.finish(result, started, domain.CollectionNotAvailable, "ROOT_REJECTED"), nil
	}
	view := s.view
	if view == nil {
		opened, err := openView(s.Root, req.Limits.MaxBytes)
		if err != nil {
			result.Warnings = append(result.Warnings, "root_open_failed")
			return s.finish(result, started, domain.CollectionFailed, "ROOT_OPEN_FAILED"), nil
		}
		defer func() { _ = opened.Close() }()
		view = opened
	}

	record, refs, warnings, missing, err := s.readIdentity(ctx, view)
	result.RawRefs = refs
	result.Warnings = append(result.Warnings, warnings...)
	if err != nil {
		status := statusForContext(err)
		if status == domain.CollectionFailed {
			return s.finish(result, started, domain.CollectionFailed, "READ_FAILED"), nil
		}
		return s.finish(result, started, status, "MODULE_"+strings.ToUpper(status)), nil
	}

	encoded, err := identityMap(record)
	if err != nil {
		return s.finish(result, started, domain.CollectionFailed, "ENCODE_FAILED"), nil
	}
	result.Records = []map[string]any{encoded}
	if len(missing) == 0 {
		result.Completeness = domain.CompletenessComplete
		return s.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	result.Warnings = append(result.Warnings, missing...)
	return s.finish(result, started, domain.CollectionPartial, "PARTIAL_IDENTITY"), nil
}

func (s *System) readIdentity(ctx context.Context, view fileView) (identityRecord, []string, []string, []string, error) {
	if err := ctx.Err(); err != nil {
		return identityRecord{}, nil, nil, nil, err
	}
	osRelease, osRef, osWarn, err := readText(ctx, view, "etc/os-release")
	if err != nil && !isContext(err) && !isNotExist(err) && !isPermission(err) && !errors.Is(err, errTruncated) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return identityRecord{}, nil, nil, nil, ctxErr
		}
	}
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	kernel, kernelRef, kernelWarn, err := readText(ctx, view, "proc/sys/kernel/osrelease")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	arch, archRef, archWarn, err := readText(ctx, view, "proc/sys/kernel/arch")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	hostname, hostRef, hostWarn, err := readText(ctx, view, "proc/sys/kernel/hostname")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	build, buildRef, buildWarn, err := readText(ctx, view, "proc/sys/kernel/version")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	cpuinfo, cpuRef, cpuWarn, err := readText(ctx, view, "proc/cpuinfo")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	meminfo, memRef, memWarn, err := readText(ctx, view, "proc/meminfo")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	stat, statRef, statWarn, err := readText(ctx, view, "proc/stat")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	parts, partRef, partWarn, err := readText(ctx, view, "proc/partitions")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	machineRaw, machineRef, machineWarn, err := readText(ctx, view, "etc/machine-id")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}
	bootRaw, bootRef, bootWarn, err := readText(ctx, view, "proc/sys/kernel/random/boot_id")
	if isContext(err) {
		return identityRecord{}, nil, nil, nil, err
	}

	fields := parseOSRelease(osRelease)
	cpuCount, cpuModel := parseCPU(cpuinfo)
	record := identityRecord{
		OS:               firstNonEmpty(fields["ID"], "unknown"),
		Distribution:     firstNonEmpty(fields["NAME"], fields["PRETTY_NAME"], "unknown"),
		OSVersion:        firstNonEmpty(fields["VERSION_ID"], "unknown"),
		VersionCodename:  fields["VERSION_CODENAME"],
		Kernel:           strings.TrimSpace(kernel),
		KernelBuild:      strings.TrimSpace(build),
		Architecture:     strings.TrimSpace(arch),
		Hostname:         strings.TrimSpace(hostname),
		CPUCount:         cpuCount,
		CPUModel:         cpuModel,
		MemoryKB:         parseMemKB(meminfo),
		Disks:            parseDisks(parts),
		MachineIDDigest:  digestValue("machine-id", strings.TrimSpace(machineRaw)),
		BootIDDigest:     digestValue("boot-id", strings.TrimSpace(bootRaw)),
		View:             "unknown",
		ContainerSignals: []string{},
		UnknownFields:    []string{},
	}
	if btime := parseBtime(stat); btime > 0 {
		record.BootTime = time.Unix(btime, 0).UTC().Format(domain.TimeLayout)
	}
	record.View, record.ContainerSignals = detectView(view)
	record.IdentityFingerprint = fingerprint(record)

	refs := compactRefs(osRef, kernelRef, archRef, hostRef, buildRef, cpuRef, memRef, statRef, partRef, machineRef, bootRef)
	warnings := compactRefs(osWarn, kernelWarn, archWarn, hostWarn, buildWarn, cpuWarn, memWarn, statWarn, partWarn, machineWarn, bootWarn)
	missing := missingIdentity(record, machineRaw, bootRaw)
	_ = err
	return record, refs, warnings, missing, ctx.Err()
}

func missingIdentity(record identityRecord, machineRaw, bootRaw string) []string {
	var missing []string
	if record.OS == "" || record.OS == "unknown" {
		missing = append(missing, "os_unknown")
	}
	if record.Kernel == "" {
		missing = append(missing, "kernel_unknown")
	}
	if record.Architecture == "" {
		missing = append(missing, "architecture_unknown")
	}
	if record.BootTime == "" {
		missing = append(missing, "boot_time_unknown")
	}
	if record.CPUCount == 0 || record.MemoryKB == 0 {
		missing = append(missing, "resources_unknown")
	}
	if strings.TrimSpace(machineRaw) == "" {
		missing = append(missing, "machine_id_unavailable")
	}
	if strings.TrimSpace(bootRaw) == "" {
		missing = append(missing, "boot_id_unavailable")
	}
	if record.IdentityFingerprint == "" {
		missing = append(missing, "identity_fingerprint_unavailable")
	}
	return missing
}

func detectView(view fileView) (string, []string) {
	signals := make([]string, 0, 4)
	if _, err := view.Lstat(".dockerenv"); err == nil {
		signals = append(signals, "dockerenv")
	}
	if _, err := view.Lstat("run/.containerenv"); err == nil {
		signals = append(signals, "containerenv")
	}
	if data, err := view.ReadFile("proc/1/cgroup"); err == nil {
		text := strings.ToLower(string(data))
		for _, token := range []string{"docker", "containerd", "kubepods", "lxc", "podman"} {
			if strings.Contains(text, token) {
				signals = append(signals, "cgroup_"+token)
			}
		}
	}
	if len(signals) > 0 {
		return "container", signals
	}
	if data, err := view.ReadFile("proc/1/cgroup"); err == nil && strings.TrimSpace(string(data)) != "" {
		return "host", signals
	}
	return "unknown", signals
}

func fingerprint(record identityRecord) string {
	payload, err := json.Marshal(identityCanonical{
		Architecture:    record.Architecture,
		BootIDDigest:    record.BootIDDigest,
		Kernel:          record.Kernel,
		MachineIDDigest: record.MachineIDDigest,
		OS:              record.OS,
		OSVersion:       record.OSVersion,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(identityCanonicalVersion+"\n"), payload...))
	return hex.EncodeToString(sum[:])
}

func digestValue(kind, raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(digestPrefix + kind + ":" + raw))
	return hex.EncodeToString(sum[:])
}

func readText(ctx context.Context, view fileView, name string) (string, string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", "", err
	}
	data, err := view.ReadFile(name)
	ref := name
	switch {
	case err == nil:
		return string(data), ref, "", nil
	case errors.Is(err, errTruncated):
		return string(data), ref, name + "_truncated", nil
	case isNotExist(err):
		return "", "", name + "_missing", err
	case isPermission(err):
		return "", "", name + "_permission_denied", err
	default:
		if isContext(err) {
			return "", "", "", err
		}
		return "", "", name + "_unreadable", err
	}
}

func parseOSRelease(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"'`)
		out[key] = value
	}
	return out
}

func parseCPU(raw string) (int, string) {
	count := 0
	model := ""
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "processor") {
			count++
		}
		if model == "" && strings.HasPrefix(line, "model name") {
			_, value, ok := strings.Cut(line, ":")
			if ok {
				model = strings.TrimSpace(value)
			}
		}
	}
	return count, model
}

func parseMemKB(raw string) int64 {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				return value
			}
		}
	}
	return 0
}

func parseBtime(raw string) int64 {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				return value
			}
		}
	}
	return 0
}

func parseDisks(raw string) []diskRecord {
	disks := make([]diskRecord, 0)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[0] == "major" {
			continue
		}
		name := fields[3]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "sr") {
			continue
		}
		blocks, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		disks = append(disks, diskRecord{Name: name, Blocks: blocks})
	}
	return disks
}

func identityMap(record identityRecord) (map[string]any, error) {
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

func compactRefs(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (s *System) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *System) finish(result collector.Result, started time.Time, status, code string) collector.Result {
	result.Status = status
	result.EndedAt = s.now().UTC().Format(domain.TimeLayout)
	if result.EndedAt < result.StartedAt {
		result.EndedAt = started.UTC().Format(domain.TimeLayout)
	}
	result.ErrorCode = code
	if result.Records == nil {
		result.Records = []map[string]any{}
	}
	if result.Warnings == nil {
		result.Warnings = []string{}
	}
	if result.RawRefs == nil {
		result.RawRefs = []string{}
	}
	return result
}

func statusForContext(err error) string {
	if err == nil {
		return domain.CollectionFailed
	}
	if errors.Is(err, context.Canceled) {
		return domain.CollectionCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.CollectionTimeout
	}
	return domain.CollectionFailed
}

func isContext(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
