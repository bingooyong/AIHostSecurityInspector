package linux

import (
	"context"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const ModuleSecurityConfig = "security_config"

type Security struct {
	Root string
	Now  func() time.Time
	view fileView
}

type securityInventory struct {
	SSH      sshSettings     `json:"ssh"`
	Sudo     []fileMeta      `json:"sudo"`
	PAM      []fileMeta      `json:"pam"`
	Audit    subsystemStatus `json:"audit"`
	SELinux  selinuxStatus   `json:"selinux"`
	AppArmor apparmorStatus  `json:"apparmor"`
	Logging  []fileMeta      `json:"logging"`
	Firewall subsystemStatus `json:"firewall"`
	Caveats  []string        `json:"caveats"`
}

type sshSettings struct {
	PermitRootLogin        string   `json:"permit_root_login"`
	PasswordAuthentication string   `json:"password_authentication"`
	Includes               []string `json:"includes"`
	IncludeUnresolved      bool     `json:"include_unresolved"`
	Source                 string   `json:"source"`
	CompletePolicy         bool     `json:"complete_policy"`
}

type subsystemStatus struct {
	Status string `json:"status"`
	Source string `json:"source,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type selinuxStatus struct {
	Status string `json:"status"`
	Mode   string `json:"mode"`
	Source string `json:"source"`
}

type apparmorStatus struct {
	Status   string   `json:"status"`
	Profiles []string `json:"profiles"`
}

func (s Security) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	system := System(s)
	started := system.now().UTC()
	result := collector.Result{
		ModuleID: ModuleSecurityConfig, Version: collector.Version,
		StartedAt: started.Format(domain.TimeLayout), Records: []map[string]any{},
		RawRefs: []string{}, Warnings: []string{}, Status: domain.CollectionFailed, Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModuleSecurityConfig {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "security collector only implements security_config"}
	}
	if req.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Limits.Timeout)
		defer cancel()
	}
	if err := validateRoot(s.Root); err != nil {
		result.Warnings = append(result.Warnings, "collector_root_rejected")
		return system.finish(result, started, domain.CollectionNotAvailable, "ROOT_REJECTED"), nil
	}
	view := s.view
	if view == nil {
		opened, err := openView(s.Root, req.Limits.MaxBytes)
		if err != nil {
			result.Warnings = append(result.Warnings, "root_open_failed")
			return system.finish(result, started, domain.CollectionFailed, "ROOT_OPEN_FAILED"), nil
		}
		defer func() { _ = opened.Close() }()
		view = opened
	}
	inv, refs, warnings, err := readSecurity(ctx, view)
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
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_SECURITY"), nil
}

func readSecurity(ctx context.Context, view fileView) (securityInventory, []string, []string, error) {
	inv := securityInventory{
		PAM: []fileMeta{}, Logging: []fileMeta{}, Sudo: []fileMeta{}, Caveats: []string{"missing_config_is_not_compliant"},
		SSH:      sshSettings{CompletePolicy: false, Includes: []string{}},
		Audit:    subsystemStatus{Status: domain.CollectionNotAvailable},
		SELinux:  selinuxStatus{Status: domain.CollectionNotAvailable},
		AppArmor: apparmorStatus{Status: domain.CollectionNotAvailable, Profiles: []string{}},
		Firewall: subsystemStatus{Status: domain.CollectionNotAvailable},
	}
	refs := []string{}
	warnings := []string{}
	raw, ref, warn, err := readOptionalText(ctx, view, "etc/ssh/sshd_config")
	if isContext(err) {
		return inv, nil, nil, err
	}
	if ref != "" {
		refs = append(refs, ref)
	}
	if warn != "" {
		warnings = append(warnings, warn)
	}
	if raw != "" {
		inv.SSH = parseSSHD(raw)
	} else {
		inv.Caveats = append(inv.Caveats, "sshd_config_missing_not_compliant")
	}
	for _, path := range []string{"etc/sudoers", "etc/sudoers.d"} {
		if strings.HasSuffix(path, ".d") {
			for _, name := range listDir(view, path) {
				meta, mref, mwarn, metaErr := readOptionalMeta(ctx, view, path+"/"+name)
				if isContext(metaErr) {
					return inv, refs, warnings, metaErr
				}
				if meta != nil {
					inv.Sudo = append(inv.Sudo, *meta)
				}
				if mref != "" {
					refs = append(refs, mref)
				}
				if mwarn != "" {
					warnings = append(warnings, mwarn)
				}
			}
			continue
		}
		meta, mref, mwarn, metaErr := readOptionalMeta(ctx, view, path)
		if isContext(metaErr) {
			return inv, refs, warnings, metaErr
		}
		if meta != nil {
			inv.Sudo = append(inv.Sudo, *meta)
		}
		if mref != "" {
			refs = append(refs, mref)
		}
		if mwarn != "" {
			warnings = append(warnings, mwarn)
		}
	}
	for _, path := range append([]string{"etc/pam.d/sshd", "etc/pam.d/common-auth"}, listDir(view, "etc/pam.d")...) {
		meta, mref, mwarn, metaErr := readOptionalMeta(ctx, view, path)
		if isContext(metaErr) {
			return inv, refs, warnings, metaErr
		}
		if meta != nil {
			inv.PAM = append(inv.PAM, *meta)
		}
		if mref != "" {
			refs = append(refs, mref)
		}
		if mwarn != "" {
			warnings = append(warnings, mwarn)
		}
	}
	if raw, ref, warn, err = readOptionalText(ctx, view, "etc/audit/auditd.conf"); isContext(err) {
		return inv, refs, warnings, err
	} else if raw != "" {
		inv.Audit = subsystemStatus{Status: domain.CollectionSuccess, Source: "etc/audit/auditd.conf"}
		refs = append(refs, ref)
		if warn != "" {
			warnings = append(warnings, warn)
		}
	} else {
		inv.Audit.Status = domain.CollectionNotAvailable
		inv.Caveats = append(inv.Caveats, "audit_missing_not_compliant")
	}
	if raw, ref, warn, err = readOptionalText(ctx, view, "etc/selinux/config"); isContext(err) {
		return inv, refs, warnings, err
	} else if raw != "" {
		inv.SELinux = parseSELinux(raw)
		refs = append(refs, ref)
		if warn != "" {
			warnings = append(warnings, warn)
		}
	} else {
		inv.Caveats = append(inv.Caveats, "selinux_missing_not_compliant")
	}
	profiles := listDir(view, "etc/apparmor.d")
	if len(profiles) > 0 {
		inv.AppArmor = apparmorStatus{Status: domain.CollectionSuccess, Profiles: profiles}
		refs = append(refs, profiles...)
	} else {
		inv.Caveats = append(inv.Caveats, "apparmor_missing_not_compliant")
	}
	for _, path := range []string{"etc/rsyslog.conf", "etc/syslog.conf"} {
		meta, mref, mwarn, metaErr := readOptionalMeta(ctx, view, path)
		if isContext(metaErr) {
			return inv, refs, warnings, metaErr
		}
		if meta != nil {
			inv.Logging = append(inv.Logging, *meta)
		}
		if mref != "" {
			refs = append(refs, mref)
		}
		if mwarn != "" {
			warnings = append(warnings, mwarn)
		}
	}
	if fw, fref, fwarn, ferr := readOptionalText(ctx, view, "proc/net/ip_tables_names"); isContext(ferr) {
		return inv, refs, warnings, ferr
	} else if fw != "" {
		inv.Firewall = subsystemStatus{Status: domain.CollectionSuccess, Source: "proc/net/ip_tables_names"}
		refs = append(refs, fref)
	} else if fwarn != "" {
		warnings = append(warnings, fwarn)
	}
	return inv, compactRefs(refs...), compactRefs(warnings...), nil
}

func parseSSHD(raw string) sshSettings {
	set := sshSettings{Source: "etc/ssh/sshd_config", Includes: []string{}, CompletePolicy: false, IncludeUnresolved: false}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "permitrootlogin":
			set.PermitRootLogin = fields[1]
		case "passwordauthentication":
			set.PasswordAuthentication = fields[1]
		case "include":
			set.Includes = append(set.Includes, fields[1])
			set.IncludeUnresolved = true
			set.CompletePolicy = false
		}
	}
	if !set.IncludeUnresolved {
		set.CompletePolicy = true
	}
	return set
}

func parseSELinux(raw string) selinuxStatus {
	st := selinuxStatus{Status: domain.CollectionSuccess, Source: "etc/selinux/config", Mode: "unknown"}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "SELINUX" {
			st.Mode = value
		}
	}
	return st
}
