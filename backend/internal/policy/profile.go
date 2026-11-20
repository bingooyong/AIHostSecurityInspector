// Package policy describes fixed, read-only offline scan profiles.
package policy

import "errors"

type Limits struct {
	TimeoutSeconds            int      `json:"timeout_seconds"`
	MaxConcurrency            int      `json:"max_concurrency"`
	MaxFiles                  int      `json:"max_files"`
	MaxFileSizeBytes          int64    `json:"max_file_size_bytes"`
	AllowedPaths              []string `json:"allowed_paths"`
	ExcludedPaths             []string `json:"excluded_paths"`
	ExcludedMountTypes        []string `json:"excluded_mount_types"`
	IOMaxBytesPerSecond       int64    `json:"io_max_bytes_per_second"`
	StopOnResourcePressure    bool     `json:"stop_on_resource_pressure"`
	MaintenanceWindowRequired bool     `json:"maintenance_window_required"`
	Enforced                  bool     `json:"enforced"`
}

type Profile struct {
	Name             string   `json:"name"`
	Modules          []string `json:"modules"`
	Tools            []string `json:"tools"`
	ApprovalRequired bool     `json:"approval_required"`
	Limits           Limits   `json:"limits"`
	EstimatedImpact  string   `json:"estimated_impact"`
}

func Get(name string) (Profile, error) {
	quick := []string{"host_identity", "process_inventory", "network_inventory", "account_inventory", "service_inventory", "persistence_inventory", "security_config"}
	p := Profile{Name: name, Modules: quick, Tools: []string{}, Limits: Limits{TimeoutSeconds: 900, MaxConcurrency: 2, MaxFiles: 10000, MaxFileSizeBytes: 32 << 20, AllowedPaths: []string{}, ExcludedPaths: []string{"/proc", "/sys", "/dev", "/run", "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/docker", "/var/backups", "/backup"}, ExcludedMountTypes: []string{"nfs", "nfs4", "cifs", "fuse", "smbfs"}, IOMaxBytesPerSecond: 10 << 20, StopOnResourcePressure: true}, EstimatedImpact: "Offline plan only; no target accessed and no resource limits executed."}
	switch name {
	case "quick":
	case "standard", "deep":
		p.Modules = append(p.Modules, "package_inventory", "vulnerability_correlation", "baseline_assessment", "targeted_file_scan")
		p.Limits.AllowedPaths = []string{"/usr/local/bin", "/usr/local/sbin"}
		p.Tools = []string{"lynis"}
		if name == "deep" {
			p.Modules = append(p.Modules, "file_integrity", "yara_scan", "log_analysis")
			p.Tools = append(p.Tools, "yara")
			p.ApprovalRequired = true
			p.Limits.MaintenanceWindowRequired = true
			p.Limits.MaxFiles = 100000
			p.Limits.TimeoutSeconds = 1800
		}
	case "incident-response":
		p.Modules = []string{"host_identity", "process_inventory", "network_inventory", "targeted_event_evidence"}
		p.ApprovalRequired = true
		p.Limits.MaintenanceWindowRequired = true
		p.Limits.MaxConcurrency = 1
	default:
		return Profile{}, errors.New("invalid profile")
	}
	return p, nil
}
