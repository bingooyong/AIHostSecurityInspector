package domain

import (
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
)

const OSUnknown = "unknown"

type HostRecord struct {
	HostID          string
	Hostname        string
	Addresses       []string
	Platform        string
	Architecture    string
	OSDistribution  string
	OSVersion       string
	Zone            string
	Environment     string
	BusinessSystem  string
	Owner           string
	Criticality     string
	Authorized      bool
	AllowedProfiles []string
	Labels          []string
	Transport       string
	AuthRef         string
	KnownHostsRef   string
	HostKeyPolicy   string
}

func HostRecordFromAsset(h asset.Host) HostRecord {
	authorized := asset.IsAuthorized(h)
	return HostRecord{
		HostID:          h.ID,
		Hostname:        h.Hostname,
		Addresses:       cloneStrings(h.Addresses),
		Platform:        h.Platform,
		Architecture:    h.Architecture,
		OSDistribution:  OSUnknown,
		OSVersion:       OSUnknown,
		Zone:            h.Zone,
		Environment:     h.Environment,
		BusinessSystem:  h.BusinessSystem,
		Owner:           h.Owner,
		Criticality:     h.Criticality,
		Authorized:      authorized,
		AllowedProfiles: cloneStrings(h.AllowedProfiles),
		Labels:          cloneStrings(h.Labels),
		Transport:       h.Connection.Transport,
		AuthRef:         h.Connection.AuthRef,
		KnownHostsRef:   h.Connection.KnownHostsRef,
		HostKeyPolicy:   h.Connection.HostKeyPolicy,
	}
}

func (h HostRecord) Validate() error {
	if !ValidHostID(h.HostID) {
		return fail(CodeInvalidID, "host_id is invalid")
	}
	if h.OSDistribution == "" || h.OSVersion == "" {
		return fail(CodeInvalidCanonical, "os fields cannot be empty; use unknown")
	}
	if h.HostKeyPolicy != "strict" {
		return fail(CodeInvalidCanonical, "host key policy must remain strict")
	}
	return nil
}
