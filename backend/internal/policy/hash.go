package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const (
	PolicyID      = "hostsec-builtin"
	PolicyVersion = "1.0"
	canonicalV1   = "policy-canonical-v1"
)

type canonicalPolicy struct {
	CanonicalVersion string   `json:"canonical_version"`
	PolicyID         string   `json:"policy_id"`
	PolicyVersion    string   `json:"policy_version"`
	Name             string   `json:"name"`
	Modules          []string `json:"modules"`
	Tools            []string `json:"tools"`
	ApprovalRequired bool     `json:"approval_required"`
	Limits           Limits   `json:"limits"`
}

func Hash(profile Profile) (string, error) {
	payload, err := json.Marshal(canonicalPolicy{
		CanonicalVersion: canonicalV1,
		PolicyID:         PolicyID,
		PolicyVersion:    PolicyVersion,
		Name:             profile.Name,
		Modules:          append([]string{}, profile.Modules...),
		Tools:            append([]string{}, profile.Tools...),
		ApprovalRequired: profile.ApprovalRequired,
		Limits:           profile.Limits,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(canonicalV1+"\n"), payload...))
	return hex.EncodeToString(sum[:]), nil
}

func SortedCopy(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
