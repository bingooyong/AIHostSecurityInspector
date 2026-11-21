package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

const (
	RoleOperator = "operator"
	RoleApprover = "approver"
	RoleAuditor  = "auditor"

	ActionListHosts       = "list_hosts"
	ActionListProfiles    = "list_profiles"
	ActionPlan            = "plan"
	ActionRequestApproval = "request_approval"
	ActionGrantApproval   = "grant_approval"
	ActionRunFixture      = "run_fixture"
	ActionReadScan        = "read_scan"
	ActionAnalyze         = "analyze"
	ActionReport          = "report"
)

var (
	ErrIdentity     = errors.New("caller identity is not authorized")
	ErrRole         = errors.New("principal role is not permitted for this action")
	ErrZone         = errors.New("principal is not authorized for host zone or business system")
	ErrSelfAssert   = errors.New("roles, zones, and privileges cannot be self-asserted")
	ErrInherit      = errors.New("agent identity must inherit the caller and cannot expand scope")
	ErrUnknownRole  = errors.New("unknown role is not an implicit administrator")
	ErrRevoked      = errors.New("principal has been revoked")
	ErrNoAdminSuper = errors.New("there is no implicit admin superuser")
)

type Principal struct {
	ID              string   `json:"id"`
	Roles           []string `json:"roles"`
	Zones           []string `json:"zones"`
	BusinessSystems []string `json:"business_systems"`
	InheritedFrom   string   `json:"inherited_from,omitempty"`
	AgentID         string   `json:"agent_id,omitempty"`
}

type Directory struct {
	SchemaVersion string      `json:"schema_version"`
	Note          string      `json:"note"`
	Principals    []Principal `json:"principals"`
	revoked       map[string]struct{}
}

func LoadDirectory(path string) (Directory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Directory{}, err
	}
	return ParseDirectory(raw)
}

func ParseDirectory(raw []byte) (Directory, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var dir Directory
	if err := dec.Decode(&dir); err != nil {
		return Directory{}, err
	}
	if dir.SchemaVersion != "1.0" {
		return Directory{}, errors.New("identity directory schema is unsupported")
	}
	seen := map[string]struct{}{}
	for i, principal := range dir.Principals {
		if err := principal.validate(); err != nil {
			return Directory{}, err
		}
		if _, ok := seen[principal.ID]; ok {
			return Directory{}, errors.New("duplicate principal")
		}
		seen[principal.ID] = struct{}{}
		dir.Principals[i] = principal
	}
	dir.revoked = map[string]struct{}{}
	return dir, nil
}

func (d Directory) Lookup(id string) (Principal, error) {
	if id == "" || !domain.ValidEntityID(id) {
		return Principal{}, ErrIdentity
	}
	if _, ok := d.revoked[id]; ok {
		return Principal{}, ErrRevoked
	}
	for _, principal := range d.Principals {
		if principal.ID == id {
			if _, ok := d.revoked[id]; ok {
				return Principal{}, ErrRevoked
			}
			return principal, nil
		}
	}
	return Principal{}, ErrIdentity
}

func (d *Directory) Revoke(id string) error {
	if d.revoked == nil {
		d.revoked = map[string]struct{}{}
	}
	if _, err := d.Lookup(id); err != nil && !errors.Is(err, ErrRevoked) {
		return err
	}
	d.revoked[id] = struct{}{}
	return nil
}

func (p Principal) validate() error {
	if !domain.ValidEntityID(p.ID) {
		return ErrIdentity
	}
	if len(p.Roles) == 0 || len(p.Zones) == 0 || len(p.BusinessSystems) == 0 {
		return ErrIdentity
	}
	for _, role := range p.Roles {
		switch role {
		case RoleOperator, RoleApprover, RoleAuditor:
		case "admin", "root", "superuser":
			return ErrNoAdminSuper
		default:
			return ErrUnknownRole
		}
	}
	return nil
}

func (p Principal) HasRole(role string) bool {
	for _, item := range p.Roles {
		if item == role {
			return true
		}
	}
	return false
}

func (p Principal) Can(action string) error {
	if err := p.validate(); err != nil {
		return err
	}
	allowed := map[string][]string{
		ActionListHosts:       {RoleOperator, RoleApprover, RoleAuditor},
		ActionListProfiles:    {RoleOperator, RoleApprover, RoleAuditor},
		ActionPlan:            {RoleOperator},
		ActionRequestApproval: {RoleOperator},
		ActionGrantApproval:   {RoleApprover},
		ActionRunFixture:      {RoleOperator},
		ActionReadScan:        {RoleOperator, RoleApprover, RoleAuditor},
		ActionAnalyze:         {RoleOperator},
		ActionReport:          {RoleOperator, RoleApprover, RoleAuditor},
	}
	roles, ok := allowed[action]
	if !ok {
		return ErrRole
	}
	for _, role := range roles {
		if p.HasRole(role) {
			return nil
		}
	}
	return ErrRole
}

func (p Principal) AllowsHost(host asset.Host) error {
	if !asset.IsAuthorized(host) {
		return ErrAuth
	}
	if !contains(p.Zones, host.Zone) || !contains(p.BusinessSystems, host.BusinessSystem) {
		return ErrZone
	}
	return nil
}

func (p Principal) FilterHosts(hosts []asset.Host) []asset.Host {
	out := make([]asset.Host, 0, len(hosts))
	for _, host := range hosts {
		if p.AllowsHost(host) == nil {
			out = append(out, host)
		}
	}
	return out
}

func (p Principal) InheritAgent(agentID string) (Principal, error) {
	if p.InheritedFrom != "" || p.AgentID != "" {
		return Principal{}, ErrInherit
	}
	if !domain.ValidEntityID(agentID) || agentID == p.ID {
		return Principal{}, ErrInherit
	}
	child := Principal{
		ID:              agentID,
		Roles:           append([]string{}, p.Roles...),
		Zones:           append([]string{}, p.Zones...),
		BusinessSystems: append([]string{}, p.BusinessSystems...),
		InheritedFrom:   p.ID,
		AgentID:         agentID,
	}
	if err := child.validate(); err != nil {
		return Principal{}, err
	}
	return child, nil
}

func (p Principal) Expand(roles, zones, business []string) error {
	if len(roles) > 0 || len(zones) > 0 || len(business) > 0 {
		return ErrSelfAssert
	}
	return nil
}

func SelectFor(ctx context.Context, inv asset.Inventory, principal Principal, hostID, targets, profileName string) ([]asset.Host, policy.Profile, error) {
	hosts, profile, err := Select(ctx, inv, hostID, targets, profileName)
	if err != nil {
		return nil, policy.Profile{}, err
	}
	for _, host := range hosts {
		if err := principal.AllowsHost(host); err != nil {
			return nil, policy.Profile{}, err
		}
	}
	return hosts, profile, nil
}

func contains(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
