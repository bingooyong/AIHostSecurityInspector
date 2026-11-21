package authorization

import (
	"context"
	"errors"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
)

var (
	ErrSelector = errors.New("invalid target selector")
	ErrAuth     = errors.New("host not authorized")
	ErrProfile  = errors.New("profile not authorized")
)

func Select(ctx context.Context, inv asset.Inventory, hostID, targets, profileName string) ([]asset.Host, policy.Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, policy.Profile{}, err
	}
	if err := inv.Validate(); err != nil {
		return nil, policy.Profile{}, err
	}
	if (hostID == "") == (targets == "") {
		return nil, policy.Profile{}, ErrSelector
	}
	profile, err := policy.Get(profileName)
	if err != nil {
		return nil, policy.Profile{}, err
	}
	var ids []string
	if hostID != "" {
		if !asset.ValidHostID(hostID) {
			return nil, policy.Profile{}, ErrSelector
		}
		ids = []string{hostID}
	} else {
		if !strings.HasPrefix(targets, "group:") {
			return nil, policy.Profile{}, ErrSelector
		}
		name := strings.TrimPrefix(targets, "group:")
		group, ok := inv.Groups[name]
		if !asset.ValidID(name) || !ok || len(group.Hosts) == 0 {
			return nil, policy.Profile{}, ErrSelector
		}
		ids = group.Hosts
	}
	byID := make(map[string]asset.Host, len(inv.Hosts))
	for _, host := range inv.Hosts {
		byID[host.ID] = host
	}
	selected := make([]asset.Host, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, policy.Profile{}, err
		}
		host, ok := byID[id]
		if !ok || !asset.IsAuthorized(host) {
			return nil, policy.Profile{}, ErrAuth
		}
		allowed := false
		for _, name := range host.AllowedProfiles {
			if name == profile.Name {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, policy.Profile{}, ErrProfile
		}
		selected = append(selected, host)
	}
	return selected, profile, nil
}
