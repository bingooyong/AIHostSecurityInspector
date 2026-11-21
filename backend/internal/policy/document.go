package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const DocumentSchemaVersion = "1.0"

var allowedModules = map[string]bool{
	"host_identity": true, "process_inventory": true, "network_inventory": true,
	"account_inventory": true, "service_inventory": true, "persistence_inventory": true,
	"security_config": true, "package_inventory": true, "vulnerability_correlation": true,
	"baseline_assessment": true, "targeted_file_scan": true, "file_integrity": true,
	"yara_scan": true, "log_analysis": true, "targeted_event_evidence": true,
}

var allowedTools = map[string]bool{"lynis": true, "yara": true, "osquery": true, "openscap": true, "clamav": true}

type Document struct {
	SchemaVersion    string    `json:"schema_version"`
	PolicyID         string    `json:"policy_id"`
	PolicyVersion    string    `json:"policy_version"`
	CanonicalVersion string    `json:"canonical_version"`
	Mode             string    `json:"mode"`
	Profiles         []Profile `json:"profiles"`
}

func BuiltinDocument() (Document, error) {
	names := []string{domain.ProfileQuick, domain.ProfileStandard, domain.ProfileDeep, domain.ProfileIncidentResponse}
	profiles := make([]Profile, 0, len(names))
	for _, name := range names {
		profile, err := Get(name)
		if err != nil {
			return Document{}, err
		}
		profiles = append(profiles, profile)
	}
	doc := Document{
		SchemaVersion: DocumentSchemaVersion, PolicyID: PolicyID, PolicyVersion: PolicyVersion,
		CanonicalVersion: canonicalV1, Mode: domain.ModeReadOnly, Profiles: profiles,
	}
	if err := doc.Validate(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func (d Document) Validate() error {
	if d.SchemaVersion != DocumentSchemaVersion || d.CanonicalVersion != canonicalV1 {
		return errors.New("unsupported policy schema")
	}
	if d.PolicyID != PolicyID || !domain.ValidVersion(d.PolicyVersion) {
		return errors.New("policy identity is invalid")
	}
	if d.Mode != domain.ModeReadOnly {
		return errors.New("policy mode must be READ_ONLY")
	}
	if len(d.Profiles) != 4 {
		return errors.New("policy must define exactly the four MVP profiles")
	}
	seen := map[string]bool{}
	for _, profile := range d.Profiles {
		if !domain.ValidProfile(profile.Name) || seen[profile.Name] {
			return errors.New("profile name is invalid or duplicated")
		}
		seen[profile.Name] = true
		if err := validateProfile(profile); err != nil {
			return err
		}
	}
	for _, name := range []string{domain.ProfileQuick, domain.ProfileStandard, domain.ProfileDeep, domain.ProfileIncidentResponse} {
		if !seen[name] {
			return errors.New("missing required profile")
		}
	}
	return nil
}

func validateProfile(profile Profile) error {
	if profile.Limits.Enforced {
		return errors.New("policy limits cannot claim enforcement")
	}
	if !profile.Limits.StopOnResourcePressure {
		return errors.New("stop_on_resource_pressure cannot be disabled")
	}
	if profile.ApprovalRequired != (profile.Name == domain.ProfileDeep || profile.Name == domain.ProfileIncidentResponse) {
		return errors.New("approval_required does not match profile")
	}
	if profile.ApprovalRequired && !profile.Limits.MaintenanceWindowRequired {
		return errors.New("approval profiles require a maintenance window")
	}
	if profile.Limits.TimeoutSeconds < 1 || profile.Limits.TimeoutSeconds > 1800 ||
		profile.Limits.MaxConcurrency < 1 || profile.Limits.MaxConcurrency > 2 ||
		profile.Limits.MaxFiles < 1 || profile.Limits.MaxFiles > 100000 ||
		profile.Limits.MaxFileSizeBytes < 1 || profile.Limits.MaxFileSizeBytes > 32<<20 ||
		profile.Limits.IOMaxBytesPerSecond < 1 || profile.Limits.IOMaxBytesPerSecond > 10<<20 {
		return errors.New("policy limits are out of range")
	}
	if len(profile.Modules) == 0 {
		return errors.New("profile modules are required")
	}
	for _, module := range profile.Modules {
		if !allowedModules[module] || strings.ContainsAny(module, " ;|&$`") {
			return errors.New("policy contains an unknown or unsafe module")
		}
	}
	for _, tool := range profile.Tools {
		if !allowedTools[tool] || strings.ContainsAny(tool, " ;|&$`") {
			return errors.New("policy contains an unknown or unsafe tool")
		}
	}
	return nil
}

func Load(path string) (Document, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Document{}, errors.New("policy document is invalid")
	}
	if err := doc.Validate(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func (d Document) Profile(name string) (Profile, error) {
	for _, profile := range d.Profiles {
		if profile.Name == name {
			return profile, nil
		}
	}
	return Profile{}, errors.New("invalid profile")
}

func CurrentHash(name string) (string, error) {
	profile, err := Get(name)
	if err != nil {
		return "", err
	}
	return Hash(profile)
}
