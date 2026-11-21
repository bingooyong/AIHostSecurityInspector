package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"go.yaml.in/yaml/v4"
	"go.yaml.in/yaml/v4/plugin/loaderlimits"
)

const maxCollectionDocBytes = 1 << 20

var (
	ErrAllowlist = errors.New("collection allowlist is invalid")
	ErrBindings  = errors.New("collection bindings are invalid")
	ErrBinding   = errors.New("authorized collection request was rejected")
)

// CollectionAllowlist is the explicit, per-run list of host IDs the operator
// opts into. Inventory authorization alone is never sufficient.
type CollectionAllowlist struct {
	Version int      `json:"version" yaml:"version"`
	Profile string   `json:"profile,omitempty" yaml:"profile,omitempty"`
	Hosts   []string `json:"hosts" yaml:"hosts"`
}

// HostBinding maps one inventory host_id to a local SSH identity and a
// strict known_hosts file. Paths must be absolute regular files.
type HostBinding struct {
	HostID         string `json:"host_id" yaml:"host_id"`
	IdentityPath   string `json:"identity_path,omitempty" yaml:"identity_path,omitempty"`
	KnownHostsPath string `json:"known_hosts_path,omitempty" yaml:"known_hosts_path,omitempty"`
}

// CollectionBindings is the operator-supplied credential map for a run.
type CollectionBindings struct {
	Version int           `json:"version" yaml:"version"`
	Hosts   []HostBinding `json:"hosts" yaml:"hosts"`
}

func LoadAllowlist(ctx context.Context, path string) (CollectionAllowlist, error) {
	var out CollectionAllowlist
	if err := loadCollectionDoc(ctx, path, &out); err != nil {
		return CollectionAllowlist{}, err
	}
	if err := out.Validate(); err != nil {
		return CollectionAllowlist{}, err
	}
	return out, nil
}

func (a CollectionAllowlist) Validate() error {
	if a.Version != 1 {
		return ErrAllowlist
	}
	if a.Profile != "" && !domain.ValidProfile(a.Profile) {
		return ErrAllowlist
	}
	if len(a.Hosts) == 0 || len(a.Hosts) > asset.MaxHosts {
		return ErrAllowlist
	}
	seen := map[string]struct{}{}
	for _, id := range a.Hosts {
		if !asset.ValidHostID(id) {
			return ErrAllowlist
		}
		if _, ok := seen[id]; ok {
			return ErrAllowlist
		}
		seen[id] = struct{}{}
	}
	return nil
}

func LoadBindings(ctx context.Context, path string) (CollectionBindings, error) {
	var out CollectionBindings
	if err := loadCollectionDoc(ctx, path, &out); err != nil {
		return CollectionBindings{}, err
	}
	if err := out.Validate(); err != nil {
		return CollectionBindings{}, err
	}
	return out, nil
}

func (b CollectionBindings) Validate() error {
	if b.Version != 1 {
		return ErrBindings
	}
	if len(b.Hosts) > asset.MaxHosts {
		return ErrBindings
	}
	seen := map[string]struct{}{}
	for _, host := range b.Hosts {
		if !asset.ValidHostID(host.HostID) {
			return ErrBindings
		}
		if _, ok := seen[host.HostID]; ok {
			return ErrBindings
		}
		seen[host.HostID] = struct{}{}
		if err := validateAbsPath(host.IdentityPath); err != nil {
			return err
		}
		if err := validateAbsPath(host.KnownHostsPath); err != nil {
			return err
		}
		if host.IdentityPath == "" && host.KnownHostsPath == "" {
			return ErrBindings
		}
	}
	return nil
}

func (b CollectionBindings) Lookup(hostID string) (HostBinding, bool) {
	for _, host := range b.Hosts {
		if host.HostID == hostID {
			return host, true
		}
	}
	return HostBinding{}, false
}

func validateAbsPath(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || strings.ContainsAny(path, "\n\r") || len(path) > 4096 {
		return ErrBindings
	}
	if path != filepath.Clean(path) {
		return ErrBindings
	}
	return nil
}

func loadCollectionDoc(ctx context.Context, path string, dest any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := readBoundedRegular(path, maxCollectionDocBytes)
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ErrAllowlist
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if !json.Valid(trimmed) {
			return ErrAllowlist
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dest); err != nil {
			return ErrAllowlist
		}
		return nil
	}
	opts := []yaml.Option{yaml.WithKnownFields(), yaml.WithUniqueKeys(), yaml.WithPlugin(loaderlimits.New(loaderlimits.DepthValue(8), loaderlimits.AliasNone()))}
	if err := yaml.Load(trimmed, dest, opts...); err != nil {
		return ErrAllowlist
	}
	return nil
}

func readBoundedRegular(path string, max int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open file", ErrAllowlist)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, ErrAllowlist
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, ErrAllowlist
	}
	return data, nil
}
