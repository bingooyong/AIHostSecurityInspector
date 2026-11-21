package app

import "github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"

const (
	DefaultPageLimit = 20
	MaxPageLimit     = 100
)

type Page[T any] struct {
	Items      []T  `json:"items"`
	Total      int  `json:"total"`
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	NextOffset *int `json:"next_offset"`
}

type PublicHost struct {
	HostID          string   `json:"host_id"`
	Hostname        string   `json:"hostname"`
	Zone            string   `json:"zone"`
	Environment     string   `json:"environment"`
	BusinessSystem  string   `json:"business_system"`
	Owner           string   `json:"owner"`
	Authorized      bool     `json:"authorized"`
	AllowedProfiles []string `json:"allowed_profiles"`
}

func Paginate[T any](items []T, limit, offset int) (Page[T], error) {
	if limit < 0 || offset < 0 || limit > MaxPageLimit {
		return Page[T]{}, fail(CodeSchema, "page is out of range")
	}
	if limit == 0 {
		limit = DefaultPageLimit
	}
	total := len(items)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := Page[T]{Items: items[offset:end], Total: total, Limit: limit, Offset: offset}
	if page.Items == nil {
		page.Items = []T{}
	}
	if end < total {
		next := end
		page.NextOffset = &next
	}
	return page, nil
}

func PublicHosts(hosts []asset.Host) []PublicHost {
	out := make([]PublicHost, 0, len(hosts))
	for _, host := range hosts {
		profiles := append([]string{}, host.AllowedProfiles...)
		out = append(out, PublicHost{
			HostID:          host.ID,
			Hostname:        host.Hostname,
			Zone:            host.Zone,
			Environment:     host.Environment,
			BusinessSystem:  host.BusinessSystem,
			Owner:           host.Owner,
			Authorized:      asset.IsAuthorized(host),
			AllowedProfiles: profiles,
		})
	}
	return out
}
