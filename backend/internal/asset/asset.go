// Package asset loads bounded inventory documents and validates authorization metadata.
package asset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"go.yaml.in/yaml/v4"
	"go.yaml.in/yaml/v4/plugin/loaderlimits"
)

const (
	MaxBytes = 1 << 20
	MaxHosts = 1000
)

var (
	ErrInvalid      = errors.New("invalid asset document")
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	refPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	userPattern     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

type Inventory struct {
	Version int              `json:"version" yaml:"version"`
	Hosts   []Host           `json:"hosts" yaml:"hosts"`
	Groups  map[string]Group `json:"groups" yaml:"groups"`
}

type Host struct {
	ID              string     `json:"host_id" yaml:"host_id"`
	Hostname        string     `json:"hostname" yaml:"hostname"`
	Addresses       []string   `json:"addresses" yaml:"addresses"`
	Platform        string     `json:"platform" yaml:"platform"`
	Architecture    string     `json:"architecture" yaml:"architecture"`
	Zone            string     `json:"zone" yaml:"zone"`
	Environment     string     `json:"environment" yaml:"environment"`
	BusinessSystem  string     `json:"business_system" yaml:"business_system"`
	Owner           string     `json:"owner" yaml:"owner"`
	Criticality     string     `json:"criticality" yaml:"criticality"`
	Authorized      *bool      `json:"authorized" yaml:"authorized"`
	AllowedProfiles []string   `json:"allowed_profiles" yaml:"allowed_profiles"`
	Labels          []string   `json:"labels" yaml:"labels"`
	Connection      Connection `json:"connection" yaml:"connection"`
}

type Connection struct {
	Transport     string `json:"transport" yaml:"transport"`
	Port          int    `json:"port,omitempty" yaml:"port"`
	User          string `json:"user,omitempty" yaml:"user"`
	AuthRef       string `json:"auth_ref,omitempty" yaml:"auth_ref"`
	KnownHostsRef string `json:"known_hosts_ref,omitempty" yaml:"known_hosts_ref"`
	HostKeyPolicy string `json:"host_key_policy" yaml:"host_key_policy"`
}

type Group struct {
	Hosts []string `json:"hosts" yaml:"hosts"`
}

func ValidID(s string) bool { return idPattern.MatchString(s) }

// ValidHostID excludes network addresses even when they match the identifier alphabet.
func ValidHostID(s string) bool {
	if !ValidID(s) {
		return false
	}
	_, err := netip.ParseAddr(s)
	return err != nil
}
func IsAuthorized(h Host) bool { return h.Authorized != nil && *h.Authorized }
func ValidProfile(p string) bool {
	return p == "quick" || p == "standard" || p == "deep" || p == "incident-response"
}

// Load rejects special files and symlinks before parsing. No network or target access occurs.
func Load(ctx context.Context, path string) (*Inventory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Nonblocking/no-follow open avoids FIFO blocking and symlink substitution.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot open asset file")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxBytes {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || len(b) > MaxBytes {
		return nil, ErrInvalid
	}
	return Parse(ctx, b)
}

// Parse accepts exactly one YAML or JSON document. Parser errors never expose source values.
func Parse(ctx context.Context, data []byte) (*Inventory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaxBytes {
		return nil, ErrInvalid
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, ErrInvalid
	}
	// JSON-looking input must actually be JSON, not permissive YAML flow syntax.
	if (trimmed[0] == '{' || trimmed[0] == '[') && !json.Valid(trimmed) {
		return nil, ErrInvalid
	}
	var inv Inventory
	if trimmed[0] == '{' || trimmed[0] == '[' {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		if !validJSONTokens(decoder, 0) {
			return nil, ErrInvalid
		}
		// Check field spellings explicitly: encoding/json otherwise accepts case-insensitive tags.
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &raw); err != nil || !exactFields(raw, "version", "hosts", "groups") {
			return nil, ErrInvalid
		}
		var hosts []map[string]json.RawMessage
		if err := json.Unmarshal(raw["hosts"], &hosts); err != nil {
			return nil, ErrInvalid
		}
		for _, host := range hosts {
			if !exactFields(host, "host_id", "hostname", "addresses", "platform", "architecture", "zone", "environment", "business_system", "owner", "criticality", "authorized", "allowed_profiles", "labels", "connection") {
				return nil, ErrInvalid
			}
			var connection map[string]json.RawMessage
			if err := json.Unmarshal(host["connection"], &connection); err != nil || !exactFields(connection, "transport", "port", "user", "auth_ref", "known_hosts_ref", "host_key_policy") {
				return nil, ErrInvalid
			}
		}
		var groups map[string]map[string]json.RawMessage
		if err := json.Unmarshal(raw["groups"], &groups); err != nil {
			return nil, ErrInvalid
		}
		for _, group := range groups {
			if !exactFields(group, "hosts") {
				return nil, ErrInvalid
			}
		}
		decoder = json.NewDecoder(bytes.NewReader(trimmed))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inv); err != nil {
			return nil, ErrInvalid
		}
	} else {
		opts := []yaml.Option{yaml.WithKnownFields(), yaml.WithUniqueKeys(), yaml.WithPlugin(loaderlimits.New(loaderlimits.DepthValue(16), loaderlimits.AliasNone()))}
		var node yaml.Node
		if err := yaml.Load(data, &node, opts...); err != nil || !validNode(&node, 0) {
			return nil, ErrInvalid
		}
		if err := node.Load(&inv, opts...); err != nil {
			return nil, ErrInvalid
		}
		// YAML's typed decoder permits numeric-to-string coercion. A JSON-compatible
		// untyped view is checked through encoding/json to require exact scalar types.
		var value any
		if err := node.Load(&value, opts...); err != nil {
			return nil, ErrInvalid
		}
		normalized, err := json.Marshal(value)
		if err != nil {
			return nil, ErrInvalid
		}
		decoder := json.NewDecoder(bytes.NewReader(normalized))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inv); err != nil {
			return nil, ErrInvalid
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	return &inv, nil
}

func exactFields(fields map[string]json.RawMessage, allowed ...string) bool {
	for key := range fields {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validJSONTokens(decoder *json.Decoder, depth int) bool {
	if depth > 16 {
		return false
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return false
			}
			seen[name] = true
			if !validJSONTokens(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !validJSONTokens(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	}
	return false
}

func validNode(n *yaml.Node, depth int) bool {
	if depth > 16 || n.Kind == yaml.AliasNode || n.Anchor != "" || (n.Kind == yaml.ScalarNode && n.Tag == "!!null") {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
				return false
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if !validNode(child, depth+1) {
			return false
		}
	}
	return true
}

func safeText(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

func uniqueStrings(v []string, min, max int, valid func(string) bool) bool {
	if len(v) < min || len(v) > max {
		return false
	}
	seen := make(map[string]bool, len(v))
	for _, s := range v {
		if !valid(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func (inv Inventory) Validate() error {
	if inv.Version != 1 || inv.Hosts == nil || len(inv.Hosts) > MaxHosts || inv.Groups == nil || len(inv.Groups) > 1000 {
		return ErrInvalid
	}
	ids := make(map[string]bool, len(inv.Hosts))
	for _, h := range inv.Hosts {
		if !ValidHostID(h.ID) || ids[h.ID] || !hostnamePattern.MatchString(h.Hostname) || h.Platform != "linux" || (h.Architecture != "x86_64" && h.Architecture != "arm64") || h.Authorized == nil {
			return ErrInvalid
		}
		ids[h.ID] = true
		if !safeText(h.Zone) || !safeText(h.BusinessSystem) || !safeText(h.Owner) || (h.Environment != "TEST" && h.Environment != "UAT" && h.Environment != "PROD") {
			return ErrInvalid
		}
		if h.Criticality != "low" && h.Criticality != "medium" && h.Criticality != "high" && h.Criticality != "critical" {
			return ErrInvalid
		}
		if !uniqueStrings(h.Addresses, 1, 16, func(s string) bool {
			a, e := netip.ParseAddr(s)
			return e == nil && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast()
		}) {
			return ErrInvalid
		}
		if !uniqueStrings(h.AllowedProfiles, 1, 4, ValidProfile) || (h.Labels == nil || !uniqueStrings(h.Labels, 0, 64, ValidID)) {
			return ErrInvalid
		}
		c := h.Connection
		if c.HostKeyPolicy != "strict" {
			return ErrInvalid
		}
		switch c.Transport {
		case "ssh":
			if c.Port < 1 || c.Port > 65535 || !userPattern.MatchString(c.User) || c.User == "root" || !refPattern.MatchString(c.AuthRef) || !refPattern.MatchString(c.KnownHostsRef) {
				return ErrInvalid
			}
		case "local":
			if c.Port != 0 || c.User != "" || c.AuthRef != "" || c.KnownHostsRef != "" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	for name, g := range inv.Groups {
		if !ValidID(name) || !uniqueStrings(g.Hosts, 1, MaxHosts, func(id string) bool { return ids[id] }) {
			return ErrInvalid
		}
	}
	return nil
}

// Authorized returns a detached filtered view. No credential references are resolved.
func (inv Inventory) Authorized() Inventory {
	out := Inventory{Version: inv.Version, Hosts: []Host{}, Groups: map[string]Group{}}
	allowed := map[string]bool{}
	for _, h := range inv.Hosts {
		if IsAuthorized(h) {
			out.Hosts = append(out.Hosts, h)
			allowed[h.ID] = true
		}
	}
	for name, g := range inv.Groups {
		ids := []string{}
		for _, id := range g.Hosts {
			if allowed[id] {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			out.Groups[name] = Group{Hosts: ids}
		}
	}
	return out
}
