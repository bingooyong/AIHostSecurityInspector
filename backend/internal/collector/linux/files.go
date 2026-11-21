package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const ModuleTargetedFileScan = "targeted_file_scan"

type Files struct {
	Root  string
	Now   func() time.Time
	Allow []string
	view  fileView
}

type fileRecord struct {
	Path     string `json:"path"`
	Mode     string `json:"mode"`
	Owner    string `json:"owner"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256,omitempty"`
	SUID     bool   `json:"suid"`
	SGID     bool   `json:"sgid"`
	Hidden   bool   `json:"hidden"`
	Symlink  bool   `json:"symlink"`
	Rejected string `json:"rejected,omitempty"`
}

func (f Files) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	system := System{Root: f.Root, Now: f.Now, view: f.view}
	started := system.now().UTC()
	result := collector.Result{
		ModuleID: ModuleTargetedFileScan, Version: collector.Version,
		StartedAt: started.Format(domain.TimeLayout), Records: []map[string]any{},
		RawRefs: []string{}, Warnings: []string{}, Status: domain.CollectionFailed, Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModuleTargetedFileScan {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "file collector only implements targeted_file_scan"}
	}
	if req.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Limits.Timeout)
		defer cancel()
	}
	if err := validateRoot(f.Root); err != nil {
		result.Warnings = append(result.Warnings, "collector_root_rejected")
		return system.finish(result, started, domain.CollectionNotAvailable, "ROOT_REJECTED"), nil
	}
	view := f.view
	if view == nil {
		opened, err := openView(f.Root, req.Limits.MaxBytes)
		if err != nil {
			result.Warnings = append(result.Warnings, "root_open_failed")
			return system.finish(result, started, domain.CollectionFailed, "ROOT_OPEN_FAILED"), nil
		}
		defer func() { _ = opened.Close() }()
		view = opened
	}
	allow := f.Allow
	if len(allow) == 0 {
		allow = []string{"usr/local/bin", "usr/local/sbin"}
	}
	max := req.Limits.MaxRecords
	if max <= 0 {
		max = 256
	}
	records, refs, warnings, err := walkAllowed(ctx, view, allow, max)
	result.RawRefs = refs
	result.Warnings = append(result.Warnings, warnings...)
	if isContext(err) {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), nil
	}
	for _, rec := range records {
		encoded, encErr := toRecordMap(rec)
		if encErr != nil {
			continue
		}
		result.Records = append(result.Records, encoded)
	}
	if len(result.Records) == 0 {
		result.Completeness = domain.CompletenessUnavailable
		return system.finish(result, started, domain.CollectionFailed, "NO_FILE_RECORDS"), nil
	}
	if len(warnings) == 0 {
		result.Completeness = domain.CompletenessComplete
		return system.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_FILES"), nil
}

func walkAllowed(ctx context.Context, view fileView, allow []string, max int) ([]fileRecord, []string, []string, error) {
	out := make([]fileRecord, 0)
	refs := make([]string, 0)
	warnings := make([]string, 0)
	for _, dir := range allow {
		dir = strings.TrimPrefix(dir, "/")
		if dir == "" || strings.Contains(dir, "..") {
			warnings = append(warnings, "path_rejected")
			continue
		}
		entries, err := view.ReadDir(dir)
		if err != nil {
			if isPermission(err) {
				warnings = append(warnings, dir+"_permission_denied")
			} else if !isNotExist(err) {
				warnings = append(warnings, dir+"_unreadable")
			}
			continue
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return out, refs, warnings, err
			}
			if len(out) >= max {
				warnings = append(warnings, "file_record_limit")
				return out, compactRefs(refs...), compactRefs(warnings...), nil
			}
			rel := path.Join(dir, entry.Name())
			rec, ref, warn := inspectFile(view, rel, entry.Name())
			out = append(out, rec)
			if ref != "" {
				refs = append(refs, ref)
			}
			if warn != "" {
				warnings = append(warnings, warn)
			}
		}
	}
	return out, compactRefs(refs...), compactRefs(warnings...), nil
}

func inspectFile(view fileView, rel, name string) (fileRecord, string, string) {
	rec := fileRecord{Path: rel, Hidden: strings.HasPrefix(name, ".")}
	info, err := view.Lstat(rel)
	if err != nil {
		if isPermission(err) {
			rec.Rejected = "permission_denied"
			return rec, "", rel + "_permission_denied"
		}
		rec.Rejected = "unreadable"
		return rec, "", rel + "_unreadable"
	}
	mode := info.Mode()
	rec.Mode = mode.String()
	rec.Size = info.Size()
	rec.Owner = fileOwner(info)
	rec.SUID = mode&fs.ModeSetuid != 0
	rec.SGID = mode&fs.ModeSetgid != 0
	if mode&fs.ModeSymlink != 0 {
		rec.Symlink = true
		rec.Rejected = "symlink_not_followed"
		return rec, rel, ""
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rec.Owner = strconv.FormatUint(uint64(st.Uid), 10)
	}
	data, readErr := view.ReadFile(rel)
	if isPermission(readErr) {
		rec.Rejected = "permission_denied"
		return rec, rel, rel + "_permission_denied"
	}
	if readErr != nil && !isNotExist(readErr) {
		return rec, rel, ""
	}
	if readErr == nil {
		sum := sha256.Sum256(data)
		rec.SHA256 = hex.EncodeToString(sum[:])
	}
	return rec, rel, ""
}
