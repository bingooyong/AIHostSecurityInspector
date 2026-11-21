package linux

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const ModuleAccountInventory = "account_inventory"

type Accounts struct {
	Root string
	Now  func() time.Time
	view fileView
	Live bool
}

type accountInventory struct {
	Users          []userRecord  `json:"users"`
	Groups         []groupRecord `json:"groups"`
	UID0           []string      `json:"uid0"`
	Sudo           []sudoRecord  `json:"sudo"`
	AuthorizedKeys []keyRecord   `json:"authorized_keys"`
	Logins         []loginRecord `json:"logins"`
	SkippedSecrets []string      `json:"skipped_secrets"`
}

type userRecord struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

type groupRecord struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

type sudoRecord struct {
	Principal string `json:"principal"`
	RunAs     string `json:"run_as"`
	NOPASSWD  bool   `json:"nopasswd"`
	Commands  string `json:"commands"`
	Source    string `json:"source"`
}

type keyRecord struct {
	User              string `json:"user"`
	Type              string `json:"type"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Source            string `json:"source"`
}

type loginRecord struct {
	User    string `json:"user"`
	Method  string `json:"method"`
	Outcome string `json:"outcome"`
	Source  string `json:"source"`
}

var skippedSecretNames = map[string]bool{
	"shadow": true, "gshadow": true, "id_rsa": true, "id_dsa": true,
	"id_ecdsa": true, "id_ed25519": true, "id_ecdsa_sk": true, "id_ed25519_sk": true,
}

func (a Accounts) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	system := System(a)
	started := system.now().UTC()
	result := collector.Result{
		ModuleID: ModuleAccountInventory, Version: collector.Version,
		StartedAt: started.Format(domain.TimeLayout), Records: []map[string]any{},
		RawRefs: []string{}, Warnings: []string{}, Status: domain.CollectionFailed, Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModuleAccountInventory {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "account collector only implements account_inventory"}
	}
	if req.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Limits.Timeout)
		defer cancel()
	}
	if err := validateRootMode(a.Root, a.Live); err != nil {
		result.Warnings = append(result.Warnings, "collector_root_rejected")
		return system.finish(result, started, domain.CollectionNotAvailable, "ROOT_REJECTED"), nil
	}
	view := a.view
	if view == nil {
		opened, err := openView(a.Root, req.Limits.MaxBytes)
		if err != nil {
			result.Warnings = append(result.Warnings, "root_open_failed")
			return system.finish(result, started, domain.CollectionFailed, "ROOT_OPEN_FAILED"), nil
		}
		defer func() { _ = opened.Close() }()
		view = opened
	}
	inv, refs, warnings, err := readAccounts(ctx, view)
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
	if len(inv.Users) == 0 {
		return system.finish(result, started, domain.CollectionFailed, "NO_ACCOUNT_RECORDS"), nil
	}
	if len(warnings) == 0 {
		result.Completeness = domain.CompletenessComplete
		return system.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_ACCOUNT"), nil
}

func readAccounts(ctx context.Context, view fileView) (accountInventory, []string, []string, error) {
	inv := accountInventory{
		Users: []userRecord{}, Groups: []groupRecord{}, UID0: []string{},
		Sudo: []sudoRecord{}, AuthorizedKeys: []keyRecord{}, Logins: []loginRecord{}, SkippedSecrets: []string{},
	}
	passwd, passwdRef, passwdWarn, err := readText(ctx, view, "etc/passwd")
	if isContext(err) {
		return inv, nil, nil, err
	}
	inv.Users, inv.UID0 = parsePasswd(passwd)
	groupRaw, groupRef, groupWarn, err := readText(ctx, view, "etc/group")
	if isContext(err) {
		return inv, nil, nil, err
	}
	inv.Groups = parseGroup(groupRaw)
	sudo, sudoRefs, sudoWarn, err := readSudo(ctx, view)
	if isContext(err) {
		return inv, nil, nil, err
	}
	inv.Sudo = sudo
	keys, keyRefs, keyWarn, skipped, err := readAuthorizedKeys(ctx, view, inv.Users)
	if isContext(err) {
		return inv, nil, nil, err
	}
	inv.AuthorizedKeys = keys
	inv.SkippedSecrets = append(inv.SkippedSecrets, skipped...)
	logins, loginRef, loginWarn, err := readLogins(ctx, view)
	if isContext(err) {
		return inv, nil, nil, err
	}
	inv.Logins = logins
	if _, shadowErr := view.Lstat("etc/shadow"); shadowErr == nil {
		inv.SkippedSecrets = append(inv.SkippedSecrets, "etc/shadow")
	}
	if _, gshadowErr := view.Lstat("etc/gshadow"); gshadowErr == nil {
		inv.SkippedSecrets = append(inv.SkippedSecrets, "etc/gshadow")
	}
	refs := compactRefs(append(append([]string{passwdRef, groupRef, loginRef}, sudoRefs...), keyRefs...)...)
	warnings := compactRefs(append(append([]string{passwdWarn, groupWarn, loginWarn}, sudoWarn...), keyWarn...)...)
	if passwd == "" {
		warnings = append(warnings, "passwd_missing")
	}
	return inv, refs, warnings, ctx.Err()
}

func parsePasswd(raw string) ([]userRecord, []string) {
	users := make([]userRecord, 0)
	uid0 := make([]string, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(fields[3])
		rec := userRecord{Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}
		users = append(users, rec)
		if uid == 0 {
			uid0 = append(uid0, rec.Name)
		}
	}
	return users, uid0
}

func parseGroup(raw string) []groupRecord {
	groups := make([]groupRecord, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		members := []string{}
		if fields[3] != "" {
			members = strings.Split(fields[3], ",")
		}
		groups = append(groups, groupRecord{Name: fields[0], GID: gid, Members: members})
	}
	return groups
}

func readSudo(ctx context.Context, view fileView) ([]sudoRecord, []string, []string, error) {
	records := make([]sudoRecord, 0)
	refs := make([]string, 0)
	warnings := make([]string, 0)
	for _, path := range append([]string{"etc/sudoers"}, listDir(view, "etc/sudoers.d")...) {
		if err := ctx.Err(); err != nil {
			return records, refs, warnings, err
		}
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
		records = append(records, parseSudoers(path, raw)...)
	}
	return records, compactRefs(refs...), compactRefs(warnings...), nil
}

func parseSudoers(source, raw string) []sudoRecord {
	out := make([]sudoRecord, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		rec := sudoRecord{Principal: fields[0], RunAs: "ALL", Commands: fields[len(fields)-1], Source: source}
		joined := strings.Join(fields[1:], " ")
		rec.NOPASSWD = strings.Contains(joined, "NOPASSWD:")
		if i := strings.Index(joined, ":"); i >= 0 {
			rec.Commands = strings.TrimSpace(joined[i+1:])
		}
		out = append(out, rec)
	}
	return out
}

func readAuthorizedKeys(ctx context.Context, view fileView, users []userRecord) ([]keyRecord, []string, []string, []string, error) {
	keys := make([]keyRecord, 0)
	refs := make([]string, 0)
	warnings := make([]string, 0)
	skipped := make([]string, 0)
	seenHome := map[string]struct{}{}
	for _, user := range users {
		home := strings.TrimPrefix(user.Home, "/")
		if home == "" || home == "nonexistent" || home == "usr/sbin" {
			continue
		}
		if _, ok := seenHome[home]; ok {
			continue
		}
		seenHome[home] = struct{}{}
		sshDir := home + "/.ssh"
		entries, dirErr := view.ReadDir(sshDir)
		if dirErr != nil {
			if isPermission(dirErr) {
				warnings = append(warnings, sshDir+"_permission_denied")
			}
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			rel := sshDir + "/" + name
			if skippedSecretNames[name] || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") {
				skipped = append(skipped, rel)
				continue
			}
			if name != "authorized_keys" && name != "authorized_keys2" {
				continue
			}
			if err := ctx.Err(); err != nil {
				return keys, refs, warnings, skipped, err
			}
			raw, ref, warn, err := readText(ctx, view, rel)
			if isContext(err) {
				return keys, refs, warnings, skipped, err
			}
			if strings.Contains(raw, "PRIVATE KEY") || strings.Contains(raw, "BEGIN OPENSSH PRIVATE KEY") {
				skipped = append(skipped, rel)
				continue
			}
			if warn != "" {
				warnings = append(warnings, warn)
			}
			if ref != "" {
				refs = append(refs, ref)
			}
			keys = append(keys, parseAuthorizedKeys(user.Name, rel, raw)...)
		}
	}
	return keys, compactRefs(refs...), compactRefs(warnings...), compactRefs(skipped...), nil
}

func parseAuthorizedKeys(user, source, raw string) []keyRecord {
	out := make([]keyRecord, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		typ, blob := fields[0], fields[1]
		if strings.HasPrefix(typ, "command=") || strings.HasPrefix(typ, "from=") {
			if len(fields) < 3 {
				continue
			}
			typ, blob = fields[1], fields[2]
		}
		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err != nil || len(decoded) == 0 {
			continue
		}
		sum := sha256.Sum256(decoded)
		out = append(out, keyRecord{User: user, Type: typ, FingerprintSHA256: hex.EncodeToString(sum[:]), Source: source})
	}
	return out
}

func readLogins(ctx context.Context, view fileView) ([]loginRecord, string, string, error) {
	raw, ref, warn, err := readText(ctx, view, "var/log/auth.log")
	if isContext(err) {
		return nil, "", "", err
	}
	if raw == "" {
		return []loginRecord{}, "", firstNonEmpty(warn, "login_records_unavailable"), err
	}
	out := make([]loginRecord, 0)
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, "sshd") {
			continue
		}
		outcome, method := "", ""
		switch {
		case strings.Contains(line, "Accepted publickey"):
			outcome, method = "accepted", "publickey"
		case strings.Contains(line, "Accepted password"):
			outcome, method = "accepted", "password"
		case strings.Contains(line, "Failed password"):
			outcome, method = "failed", "password"
		default:
			continue
		}
		user := loginUser(line)
		if user == "" {
			continue
		}
		out = append(out, loginRecord{User: user, Method: method, Outcome: outcome, Source: "var/log/auth.log"})
	}
	return out, ref, warn, nil
}

func loginUser(line string) string {
	for _, marker := range []string{" for ", " for invalid user "} {
		if i := strings.Index(line, marker); i >= 0 {
			rest := strings.TrimSpace(line[i+len(marker):])
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func listDir(view fileView, dir string) []string {
	entries, err := view.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		out = append(out, dir+"/"+entry.Name())
	}
	return out
}
