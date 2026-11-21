package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const StatusCandidate = "candidate"
const StatusTrusted = "trusted"

type Snapshot struct {
	HostID         string            `json:"host_id"`
	ScanID         string            `json:"scan_id"`
	Status         string            `json:"status"`
	UID0           []string          `json:"uid0"`
	Units          []string          `json:"units"`
	Cron           []string          `json:"cron"`
	Fingerprints   []string          `json:"fingerprints"`
	SUID           []string          `json:"suid"`
	ConfigHashes   map[string]string `json:"config_hashes"`
	ListenAllow    []string          `json:"listen_allow"`
	SuspiciousDirs []string          `json:"suspicious_dirs"`
}

func Candidate(hostID, scanID string) Snapshot {
	return Snapshot{HostID: hostID, ScanID: scanID, Status: StatusCandidate, ConfigHashes: map[string]string{}, SuspiciousDirs: []string{"/tmp", "/var/tmp", "/dev/shm"}}
}

func Load(path string) (Snapshot, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(payload, &snap); err != nil {
		return Snapshot{}, err
	}
	if snap.ConfigHashes == nil {
		snap.ConfigHashes = map[string]string{}
	}
	return snap, nil
}

func Save(path string, snap Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

func (s Snapshot) Trusted() bool {
	return s.Status == StatusTrusted && domain.ValidEntityID(s.ScanID)
}
