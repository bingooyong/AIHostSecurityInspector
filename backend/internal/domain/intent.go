package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

const (
	IntentSchemaVersion    = "1.0"
	IntentCanonicalVersion = "execution-intent-canonical-v1"
)

// IntentLimits are integer-only resource bounds captured in a signed intent.
type IntentLimits struct {
	TimeoutSeconds            int   `json:"timeout_seconds"`
	MaxConcurrency            int   `json:"max_concurrency"`
	MaxFiles                  int   `json:"max_files"`
	MaxFileSizeBytes          int64 `json:"max_file_size_bytes"`
	IOMaxBytesPerSecond       int64 `json:"io_max_bytes_per_second"`
	StopOnResourcePressure    bool  `json:"stop_on_resource_pressure"`
	MaintenanceWindowRequired bool  `json:"maintenance_window_required"`
}

type MaintenanceWindow struct {
	Timezone string `json:"timezone"`
	Start    string `json:"start"`
	End      string `json:"end"`
}

// ExecutionIntent is the signable execution vector. It excludes plan_id,
// display text, created_at, approval documents, and execution_ready flags.
type ExecutionIntent struct {
	SchemaVersion        string             `json:"schema_version"`
	CanonicalVersion     string             `json:"canonical_version"`
	RequesterPrincipal   string             `json:"requester_principal"`
	HostIDs              []string           `json:"host_ids"`
	IdentityRefs         []string           `json:"identity_refs"`
	AssetSnapshotHash    string             `json:"asset_snapshot_hash"`
	PolicyID             string             `json:"policy_id"`
	PolicyVersion        string             `json:"policy_version"`
	PolicyHash           string             `json:"policy_hash"`
	Profile              string             `json:"profile"`
	Modules              []string           `json:"modules"`
	Tools                []string           `json:"tools"`
	AllowedPaths         []string           `json:"allowed_paths"`
	ExcludedPaths        []string           `json:"excluded_paths"`
	ExcludedMountTypes   []string           `json:"excluded_mount_types"`
	Limits               IntentLimits       `json:"limits"`
	RequiredCapabilities []string           `json:"required_capabilities"`
	ValidFrom            string             `json:"valid_from"`
	ValidUntil           string             `json:"valid_until"`
	MaintenanceWindow    *MaintenanceWindow `json:"maintenance_window"`
	Mode                 string             `json:"mode"`
}

func (in ExecutionIntent) Validate() error {
	if in.SchemaVersion != IntentSchemaVersion {
		return fail(CodeSchemaVersionUnsupported, "unsupported intent schema version")
	}
	if in.CanonicalVersion != IntentCanonicalVersion {
		return fail(CodeSchemaVersionUnsupported, "unsupported intent canonical version")
	}
	if !ValidEntityID(in.RequesterPrincipal) {
		return fail(CodeInvalidID, "requester principal is invalid")
	}
	if len(in.HostIDs) == 0 || len(in.HostIDs) > 1000 || !uniqueNonEmpty(in.HostIDs, ValidHostID) {
		return fail(CodeInvalidID, "host_ids are invalid")
	}
	if len(in.IdentityRefs) != len(in.HostIDs) || !uniqueNonEmpty(in.IdentityRefs, ValidEntityID) {
		return fail(CodeInvalidID, "identity_refs must be unique and match host count")
	}
	if !ValidSHA256(in.AssetSnapshotHash) || !ValidSHA256(in.PolicyHash) {
		return fail(CodeInvalidCanonical, "asset or policy hash is not SHA-256")
	}
	if !ValidEntityID(in.PolicyID) || !ValidVersion(in.PolicyVersion) {
		return fail(CodeInvalidID, "policy identity is invalid")
	}
	if !ValidProfile(in.Profile) {
		return fail(CodeInvalidEnum, "profile is not supported")
	}
	if in.Mode != ModeReadOnly {
		return fail(CodeInvalidEnum, "mode must be READ_ONLY")
	}
	if len(in.Modules) == 0 || len(in.Modules) > 32 || !uniqueNonEmpty(in.Modules, ValidEntityID) {
		return fail(CodeInvalidID, "modules are invalid")
	}
	if len(in.Tools) > 8 || !uniqueNonEmpty(in.Tools, ValidEntityID) {
		return fail(CodeInvalidID, "tools are invalid")
	}
	if len(in.AllowedPaths) > 32 || !uniqueNonEmpty(in.AllowedPaths, validPath) {
		return fail(CodeInvalidCanonical, "allowed_paths are invalid")
	}
	if len(in.ExcludedPaths) == 0 || len(in.ExcludedPaths) > 64 || !uniqueNonEmpty(in.ExcludedPaths, validPath) {
		return fail(CodeInvalidCanonical, "excluded_paths are invalid")
	}
	if len(in.ExcludedMountTypes) == 0 || len(in.ExcludedMountTypes) > 32 || !uniqueNonEmpty(in.ExcludedMountTypes, ValidEntityID) {
		return fail(CodeInvalidCanonical, "excluded_mount_types are invalid")
	}
	if err := in.Limits.validate(in.Profile); err != nil {
		return err
	}
	if len(in.RequiredCapabilities) > 32 || !uniqueNonEmpty(in.RequiredCapabilities, ValidEntityID) {
		return fail(CodeInvalidID, "required_capabilities are invalid")
	}
	if err := requireOrder(in.ValidFrom, in.ValidUntil, true); err != nil {
		return err
	}
	from, _ := ParseUTC(in.ValidFrom)
	until, _ := ParseUTC(in.ValidUntil)
	if !until.After(from) {
		return fail(CodeInvalidTimestamp, "valid_until must be after valid_from")
	}
	if in.Limits.MaintenanceWindowRequired {
		if in.MaintenanceWindow == nil {
			return fail(CodeInvalidCanonical, "maintenance window is required")
		}
		if err := in.MaintenanceWindow.validate(); err != nil {
			return err
		}
	} else if in.MaintenanceWindow != nil {
		if err := in.MaintenanceWindow.validate(); err != nil {
			return err
		}
	}
	if ProfileRequiresApproval(in.Profile) && !in.Limits.MaintenanceWindowRequired {
		return fail(CodeInvalidCanonical, "deep and incident-response require a maintenance window bound")
	}
	return nil
}

func (l IntentLimits) validate(profile string) error {
	if l.TimeoutSeconds < 1 || l.TimeoutSeconds > 1800 {
		return fail(CodeInvalidCanonical, "timeout_seconds is out of range")
	}
	if l.MaxConcurrency < 1 || l.MaxConcurrency > 2 {
		return fail(CodeInvalidCanonical, "max_concurrency is out of range")
	}
	if l.MaxFiles < 1 || l.MaxFiles > 100000 {
		return fail(CodeInvalidCanonical, "max_files is out of range")
	}
	if l.MaxFileSizeBytes < 1 || l.MaxFileSizeBytes > 32<<20 {
		return fail(CodeInvalidCanonical, "max_file_size_bytes is out of range")
	}
	if l.IOMaxBytesPerSecond < 1 || l.IOMaxBytesPerSecond > 10<<20 {
		return fail(CodeInvalidCanonical, "io_max_bytes_per_second is out of range")
	}
	if !l.StopOnResourcePressure {
		return fail(CodeInvalidCanonical, "stop_on_resource_pressure cannot be disabled")
	}
	if ProfileRequiresApproval(profile) && !l.MaintenanceWindowRequired {
		return fail(CodeInvalidCanonical, "approval profiles require a maintenance window")
	}
	return nil
}

func (w MaintenanceWindow) validate() error {
	if _, err := time.LoadLocation(w.Timezone); err != nil || w.Timezone == "" {
		return fail(CodeInvalidTimestamp, "maintenance window timezone is invalid")
	}
	if err := requireOrder(w.Start, w.End, true); err != nil {
		return err
	}
	start, _ := ParseUTC(w.Start)
	end, _ := ParseUTC(w.End)
	if !end.After(start) {
		return fail(CodeInvalidTimestamp, "maintenance window end must be after start")
	}
	return nil
}

func validPath(p string) bool {
	if !validSafeText(p, 1, 256) {
		return false
	}
	if p[0] != '/' {
		return false
	}
	if p == "/" {
		return false
	}
	return true
}

func normalizedIntent(in ExecutionIntent) ExecutionIntent {
	out := in
	out.HostIDs = sortedClone(in.HostIDs)
	out.IdentityRefs = sortedClone(in.IdentityRefs)
	out.Modules = sortedClone(in.Modules)
	out.Tools = sortedClone(in.Tools)
	out.AllowedPaths = sortedClone(in.AllowedPaths)
	out.ExcludedPaths = sortedClone(in.ExcludedPaths)
	out.ExcludedMountTypes = sortedClone(in.ExcludedMountTypes)
	out.RequiredCapabilities = sortedClone(in.RequiredCapabilities)
	if in.MaintenanceWindow != nil {
		window := *in.MaintenanceWindow
		out.MaintenanceWindow = &window
	}
	return out
}

func sortedClone(in []string) []string {
	out := cloneStrings(in)
	sort.Strings(out)
	return out
}

func CanonicalExecutionIntent(in ExecutionIntent) ([]byte, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(normalizedIntent(in))
	if err != nil {
		return nil, fail(CodeInvalidCanonical, "intent could not be canonicalized")
	}
	out := make([]byte, 0, len(IntentCanonicalVersion)+1+len(payload))
	out = append(out, IntentCanonicalVersion...)
	out = append(out, '\n')
	out = append(out, payload...)
	return out, nil
}

func HashExecutionIntent(in ExecutionIntent) (string, error) {
	canonical, err := CanonicalExecutionIntent(in)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
