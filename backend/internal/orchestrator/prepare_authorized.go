package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/approval"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/planner"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/transport/ssh"
)

// CollectionPlanRequest is the operator input for an authorized collection run.
// The inventory, allowlist, and execution intent must name the same host set.
type CollectionPlanRequest struct {
	Inventory asset.Inventory
	Allowlist authorization.CollectionAllowlist
	Bindings  authorization.CollectionBindings
	Intent    domain.ExecutionIntent
	Profile   string
}

// PreparedHost is one allowlisted target after authorization and binding checks.
type PreparedHost struct {
	Host asset.Host
	SSH  *ssh.DialConfig
}

// PrepareAuthorizedCollection validates that every allowlisted host is in the
// inventory, authorized, loopback-only in this release, bound to the execution
// intent, and (for SSH) bound to a strict per-host identity and known_hosts
// file. It never connects to a target.
func PrepareAuthorizedCollection(ctx context.Context, req CollectionPlanRequest) ([]PreparedHost, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := req.Allowlist.Validate(); err != nil {
		return nil, err
	}
	if err := req.Inventory.Validate(); err != nil {
		return nil, err
	}
	if req.Bindings.Version != 0 || len(req.Bindings.Hosts) > 0 {
		if err := req.Bindings.Validate(); err != nil {
			return nil, err
		}
	}
	profileName := req.Profile
	if profileName == "" {
		profileName = req.Allowlist.Profile
	}
	if req.Allowlist.Profile != "" && profileName != req.Allowlist.Profile {
		return nil, bindError("allowlist profile does not match the requested profile")
	}
	prof, err := policy.Get(profileName)
	if err != nil {
		return nil, err
	}
	if prof.ApprovalRequired {
		return nil, bindError("deep and incident-response are not available on the authorized collection path in this release")
	}
	if req.Intent.Profile != prof.Name {
		return nil, bindError("execution intent profile does not match the requested profile")
	}
	if !sameHostSet(req.Intent.HostIDs, req.Allowlist.Hosts) {
		return nil, bindError("execution intent host set does not match the allowlist")
	}
	for i, id := range req.Intent.HostIDs {
		if i < len(req.Intent.IdentityRefs) && req.Intent.IdentityRefs[i] != authorizationIdentityRef(id) {
			return nil, bindError("execution intent identity refs do not match the allowlisted hosts")
		}
	}
	preflight, err := planner.Preflight(ctx, req.Inventory, req.Intent, approval.TrustStore{}, nil, time.Now, nil, nil, false)
	if err != nil {
		return nil, err
	}
	if preflight.ExecutionReady || preflight.CollectorAvailable {
		return nil, bindError("preflight must not mark execution or collector ready")
	}
	byID := make(map[string]asset.Host, len(req.Inventory.Hosts))
	for _, host := range req.Inventory.Hosts {
		byID[host.ID] = host
	}
	prepared := make([]PreparedHost, 0, len(req.Allowlist.Hosts))
	seen := map[string]struct{}{}
	for _, id := range req.Allowlist.Hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := seen[id]; ok {
			return nil, bindError("allowlist contains a duplicate host")
		}
		seen[id] = struct{}{}
		host, ok := byID[id]
		if !ok {
			return nil, bindError("allowlist contains an unknown host")
		}
		if !asset.IsAuthorized(host) {
			return nil, bindError("allowlist contains a host that is not authorized")
		}
		allowed := false
		for _, name := range host.AllowedProfiles {
			if name == prof.Name {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, bindError("profile is not allowed for an allowlisted host")
		}
		if err := asset.LoopbackOnly(host); err != nil {
			return nil, bindError("authorized collection in this release accepts loopback lab targets only")
		}
		item := PreparedHost{Host: host}
		switch strings.ToLower(host.Connection.Transport) {
		case "local":
			if binding, ok := req.Bindings.Lookup(id); ok {
				if binding.IdentityPath != "" || binding.KnownHostsPath != "" {
					return nil, bindError("local transport hosts must not carry SSH bindings")
				}
			}
		case "ssh":
			cfg, err := bindSSH(host, req.Bindings)
			if err != nil {
				return nil, err
			}
			item.SSH = cfg
		default:
			return nil, bindError("host transport is not supported for authorized collection")
		}
		prepared = append(prepared, item)
	}
	return prepared, nil
}

func bindSSH(host asset.Host, bindings authorization.CollectionBindings) (*ssh.DialConfig, error) {
	binding, ok := bindings.Lookup(host.ID)
	if !ok {
		return nil, bindError("SSH host is missing an identity and known_hosts binding")
	}
	if binding.IdentityPath == "" || binding.KnownHostsPath == "" {
		return nil, bindError("SSH host binding must include identity and known_hosts paths")
	}
	if err := regularFile(binding.IdentityPath); err != nil {
		return nil, bindError("SSH identity is not a regular file")
	}
	if err := regularFile(binding.KnownHostsPath); err != nil {
		return nil, bindError("SSH known_hosts is not a regular file")
	}
	if len(host.Addresses) == 0 {
		return nil, bindError("SSH host has no addresses")
	}
	if host.Connection.HostKeyPolicy != "strict" {
		return nil, bindError("SSH host key policy must remain strict")
	}
	if err := ssh.KnownHostsCovers(binding.KnownHostsPath, host.Addresses[0], host.Connection.Port); err != nil {
		return nil, bindError("known_hosts does not bind this host address and port")
	}
	cfg := &ssh.DialConfig{
		Address:      host.Addresses[0],
		IdentityPath: binding.IdentityPath,
		Timeout:      30 * time.Second,
		Policy: ssh.Policy{
			User:           host.Connection.User,
			Port:           host.Connection.Port,
			KnownHostsPath: binding.KnownHostsPath,
			HostKeyPolicy:  "strict",
			AllowedBinary:  ssh.CollectorBinary,
		},
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func sameHostSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string{}, left...)
	b := append([]string{}, right...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func authorizationIdentityRef(hostID string) string {
	return planner.FormatIdentityRef(hostID)
}

func bindError(message string) error {
	return &domain.Error{Code: domain.CodeInvalidCanonical, Message: message}
}

func regularFile(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return bindError("SSH binding path is invalid")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return bindError("SSH binding is not a regular file")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return bindError("SSH binding is not a regular file")
	}
	return nil
}
