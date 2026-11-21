package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const SnapshotCanonicalVersion = "asset-snapshot-canonical-v1"

type Snapshot struct {
	CanonicalVersion string       `json:"canonical_version"`
	ContentHash      string       `json:"content_hash"`
	Version          int          `json:"version"`
	Hosts            []Host       `json:"hosts"`
	Groups           []namedGroup `json:"groups"`
}

type namedGroup struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

type canonicalHost struct {
	HostID          string   `json:"host_id"`
	Hostname        string   `json:"hostname"`
	Addresses       []string `json:"addresses"`
	Platform        string   `json:"platform"`
	Architecture    string   `json:"architecture"`
	Zone            string   `json:"zone"`
	Environment     string   `json:"environment"`
	BusinessSystem  string   `json:"business_system"`
	Owner           string   `json:"owner"`
	Criticality     string   `json:"criticality"`
	Authorized      bool     `json:"authorized"`
	AllowedProfiles []string `json:"allowed_profiles"`
	Labels          []string `json:"labels"`
	Transport       string   `json:"transport"`
	Port            int      `json:"port"`
	User            string   `json:"user"`
	AuthRef         string   `json:"auth_ref"`
	KnownHostsRef   string   `json:"known_hosts_ref"`
	HostKeyPolicy   string   `json:"host_key_policy"`
}

type canonicalSnapshot struct {
	CanonicalVersion string          `json:"canonical_version"`
	Version          int             `json:"version"`
	Hosts            []canonicalHost `json:"hosts"`
	Groups           []namedGroup    `json:"groups"`
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func CanonicalSnapshot(inv Inventory) ([]byte, error) {
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	hosts := append([]Host{}, inv.Hosts...)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].ID < hosts[j].ID })
	outHosts := make([]canonicalHost, 0, len(hosts))
	for _, h := range hosts {
		authorized := IsAuthorized(h)
		outHosts = append(outHosts, canonicalHost{
			HostID:          h.ID,
			Hostname:        h.Hostname,
			Addresses:       sortedCopy(h.Addresses),
			Platform:        h.Platform,
			Architecture:    h.Architecture,
			Zone:            h.Zone,
			Environment:     h.Environment,
			BusinessSystem:  h.BusinessSystem,
			Owner:           h.Owner,
			Criticality:     h.Criticality,
			Authorized:      authorized,
			AllowedProfiles: sortedCopy(h.AllowedProfiles),
			Labels:          sortedCopy(h.Labels),
			Transport:       h.Connection.Transport,
			Port:            h.Connection.Port,
			User:            h.Connection.User,
			AuthRef:         h.Connection.AuthRef,
			KnownHostsRef:   h.Connection.KnownHostsRef,
			HostKeyPolicy:   h.Connection.HostKeyPolicy,
		})
	}
	names := make([]string, 0, len(inv.Groups))
	for name := range inv.Groups {
		names = append(names, name)
	}
	sort.Strings(names)
	groups := make([]namedGroup, 0, len(names))
	for _, name := range names {
		groups = append(groups, namedGroup{Name: name, Hosts: sortedCopy(inv.Groups[name].Hosts)})
	}
	payload, err := json.Marshal(canonicalSnapshot{CanonicalVersion: SnapshotCanonicalVersion, Version: inv.Version, Hosts: outHosts, Groups: groups})
	if err != nil {
		return nil, err
	}
	out := append([]byte(SnapshotCanonicalVersion+"\n"), payload...)
	return out, nil
}

func HashSnapshot(inv Inventory) (string, error) {
	canonical, err := CanonicalSnapshot(inv)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func MakeSnapshot(inv Inventory) (*Snapshot, error) {
	hash, err := HashSnapshot(inv)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalSnapshot(inv)
	if err != nil {
		return nil, err
	}
	var parsed canonicalSnapshot
	payload := canonical[len(SnapshotCanonicalVersion)+1:]
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, err
	}
	hosts := append([]Host{}, inv.Hosts...)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].ID < hosts[j].ID })
	return &Snapshot{CanonicalVersion: SnapshotCanonicalVersion, ContentHash: hash, Version: inv.Version, Hosts: hosts, Groups: parsed.Groups}, nil
}
