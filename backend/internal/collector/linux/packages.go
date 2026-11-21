package linux

import (
	"context"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const ModulePackageInventory = "package_inventory"

type Packages struct {
	Root string
	Now  func() time.Time
	view fileView
}

type packageRecord struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Source       string `json:"source"`
	Status       string `json:"status"`
}

func (p Packages) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	system := System(p)
	started := system.now().UTC()
	result := collector.Result{
		ModuleID: ModulePackageInventory, Version: collector.Version,
		StartedAt: started.Format(domain.TimeLayout), Records: []map[string]any{},
		RawRefs: []string{}, Warnings: []string{}, Status: domain.CollectionFailed, Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModulePackageInventory {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "package collector only implements package_inventory"}
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
	records, refs, warnings, err := readPackages(ctx, view)
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
		return system.finish(result, started, domain.CollectionNotAvailable, "PACKAGE_DB_NOT_AVAILABLE"), nil
	}
	if len(warnings) == 0 {
		result.Completeness = domain.CompletenessComplete
		return system.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_PACKAGES"), nil
}

func readPackages(ctx context.Context, view fileView) ([]packageRecord, []string, []string, error) {
	raw, ref, warn, err := readOptionalText(ctx, view, "var/lib/dpkg/status")
	if isContext(err) {
		return nil, nil, nil, err
	}
	if raw != "" {
		return parseDpkgStatus(raw), compactRefs(ref), compactRefs(warn), nil
	}
	apk, apkRef, apkWarn, err := readOptionalText(ctx, view, "lib/apk/db/installed")
	if isContext(err) {
		return nil, nil, nil, err
	}
	if apk != "" {
		return parseApkInstalled(apk), compactRefs(apkRef), compactRefs(apkWarn), nil
	}
	if _, rpmErr := view.Lstat("var/lib/rpm/Packages"); rpmErr == nil {
		return nil, nil, []string{"rpm_db_unparsed"}, nil
	}
	return nil, nil, compactRefs(warn, apkWarn, "package_db_missing"), nil
}

func parseDpkgStatus(raw string) []packageRecord {
	out := make([]packageRecord, 0)
	cur := packageRecord{Source: "dpkg"}
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = packageRecord{Source: "dpkg"}
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Package":
			cur.Name = value
		case "Version":
			cur.Version = value
		case "Architecture":
			cur.Architecture = value
		case "Status":
			cur.Status = value
		}
	}
	flush()
	return out
}

func parseApkInstalled(raw string) []packageRecord {
	out := make([]packageRecord, 0)
	cur := packageRecord{Source: "apk"}
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			if cur.Name != "" {
				out = append(out, cur)
			}
			cur = packageRecord{Source: "apk"}
			continue
		}
		if strings.HasPrefix(line, "P:") {
			cur.Name = strings.TrimPrefix(line, "P:")
		}
		if strings.HasPrefix(line, "V:") {
			cur.Version = strings.TrimPrefix(line, "V:")
		}
		if strings.HasPrefix(line, "A:") {
			cur.Architecture = strings.TrimPrefix(line, "A:")
		}
	}
	if cur.Name != "" {
		out = append(out, cur)
	}
	return out
}
