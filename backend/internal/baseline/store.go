package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/sign"
)

const (
	StatusCandidate = "candidate"
	StatusTrusted   = "trusted"
	DiffUnknown     = "UNKNOWN"
	DiffUnchanged   = "UNCHANGED"
	DiffChanged     = "CHANGED"
)

var (
	ErrNotCandidate = errors.New("only a candidate snapshot can be approved")
	ErrTamper       = errors.New("approved baseline failed integrity verification")
	ErrNoApproved   = errors.New("no approved baseline")
)

type HostIdentity struct {
	HostID       string `json:"host_id"`
	OS           string `json:"os"`
	Distribution string `json:"distribution"`
}

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
	Identity       HostIdentity      `json:"identity"`
	SSHKeys        []string          `json:"ssh_keys"`
	SSHConfigHash  string            `json:"ssh_config_hash"`
	Services       []string          `json:"services"`
	PayloadHash    string            `json:"payload_hash,omitempty"`
	ApprovedBy     string            `json:"approved_by,omitempty"`
	ApprovedAt     string            `json:"approved_at,omitempty"`
}

type payload struct {
	HostID         string            `json:"host_id"`
	ScanID         string            `json:"scan_id"`
	UID0           []string          `json:"uid0"`
	Units          []string          `json:"units"`
	Cron           []string          `json:"cron"`
	Fingerprints   []string          `json:"fingerprints"`
	SUID           []string          `json:"suid"`
	ConfigHashes   map[string]string `json:"config_hashes"`
	ListenAllow    []string          `json:"listen_allow"`
	SuspiciousDirs []string          `json:"suspicious_dirs"`
	Identity       HostIdentity      `json:"identity"`
	SSHKeys        []string          `json:"ssh_keys"`
	SSHConfigHash  string            `json:"ssh_config_hash"`
	Services       []string          `json:"services"`
}

type Diff struct {
	Status    string   `json:"status"`
	Identity  []string `json:"identity"`
	SSHKeys   []string `json:"ssh_keys"`
	SSHConfig []string `json:"ssh_config"`
	Services  []string `json:"services"`
	Other     []string `json:"other"`
	Notes     []string `json:"notes"`
}

type Attempt struct {
	At     string `json:"at"`
	Action string `json:"action"`
	ScanID string `json:"scan_id"`
	Result string `json:"result"`
	Note   string `json:"note"`
}

type Record struct {
	HostID      string `json:"host_id"`
	ScanID      string `json:"scan_id"`
	PayloadHash string `json:"payload_hash"`
	ApprovedBy  string `json:"approved_by"`
	ApprovedAt  string `json:"approved_at"`
}

type Store struct {
	Dir string
}

func Candidate(hostID, scanID string) Snapshot {
	return Snapshot{
		HostID: hostID, ScanID: scanID, Status: StatusCandidate,
		ConfigHashes: map[string]string{}, SuspiciousDirs: []string{"/tmp", "/var/tmp", "/dev/shm"},
		Identity: HostIdentity{HostID: hostID},
	}
}

func HashPayload(snap Snapshot) (string, error) {
	canonical, err := sign.Canonical(payload{
		HostID: snap.HostID, ScanID: snap.ScanID, UID0: snap.UID0, Units: snap.Units, Cron: snap.Cron,
		Fingerprints: snap.Fingerprints, SUID: snap.SUID, ConfigHashes: snap.ConfigHashes,
		ListenAllow: snap.ListenAllow, SuspiciousDirs: snap.SuspiciousDirs, Identity: snap.Identity,
		SSHKeys: snap.SSHKeys, SSHConfigHash: snap.SSHConfigHash, Services: snap.Services,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
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
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}

func (s Snapshot) Trusted() bool {
	return s.Status == StatusTrusted && domain.ValidEntityID(s.ScanID) && s.PayloadHash != ""
}

func (s Store) hostDir(hostID string) string {
	return filepath.Join(s.Dir, "hosts", hostID)
}

func (s Store) RecordCandidate(snap Snapshot) error {
	if snap.Status != StatusCandidate || snap.HostID == "" || !domain.ValidEntityID(snap.ScanID) {
		return ErrNotCandidate
	}
	if err := os.MkdirAll(s.hostDir(snap.HostID), 0o700); err != nil {
		return err
	}
	if err := Save(filepath.Join(s.hostDir(snap.HostID), "candidate.json"), snap); err != nil {
		return err
	}
	return s.appendHistory(snap.HostID, Attempt{
		At: time.Now().UTC().Format(domain.TimeLayout), Action: "record_candidate",
		ScanID: snap.ScanID, Result: StatusCandidate, Note: "first or subsequent scan remains a candidate until explicitly approved",
	})
}

func (s Store) Approve(hostID, scanID, approver string, now time.Time) (Snapshot, error) {
	if approver == "" {
		return Snapshot{}, errors.New("approver is required")
	}
	snap, err := Load(filepath.Join(s.hostDir(hostID), "candidate.json"))
	if err != nil {
		return Snapshot{}, err
	}
	if snap.HostID != hostID || snap.ScanID != scanID || snap.Status != StatusCandidate {
		return Snapshot{}, ErrNotCandidate
	}
	hash, err := HashPayload(snap)
	if err != nil {
		return Snapshot{}, err
	}
	snap.Status = StatusTrusted
	snap.PayloadHash = hash
	snap.ApprovedBy = approver
	snap.ApprovedAt = now.UTC().Format(domain.TimeLayout)
	if err := Save(filepath.Join(s.hostDir(hostID), "trusted.json"), snap); err != nil {
		return Snapshot{}, err
	}
	if err := s.appendIndex(Record{
		HostID: hostID, ScanID: scanID, PayloadHash: hash, ApprovedBy: approver, ApprovedAt: snap.ApprovedAt,
	}); err != nil {
		return Snapshot{}, err
	}
	if err := s.appendHistory(hostID, Attempt{
		At: snap.ApprovedAt, Action: "approve", ScanID: scanID, Result: StatusTrusted, Note: "explicit approval bound the candidate as the trusted baseline",
	}); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

func (s Store) Approved(hostID string) (Snapshot, error) {
	snap, err := Load(filepath.Join(s.hostDir(hostID), "trusted.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return Snapshot{}, ErrNoApproved
		}
		return Snapshot{}, err
	}
	if err := s.VerifyTrusted(snap); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

func (s Store) VerifyTrusted(snap Snapshot) error {
	if !snap.Trusted() {
		return ErrTamper
	}
	hash, err := HashPayload(snap)
	if err != nil {
		return err
	}
	if hash != snap.PayloadHash {
		return ErrTamper
	}
	rec, err := s.lastIndex(snap.HostID)
	if err != nil {
		return err
	}
	if rec.PayloadHash != snap.PayloadHash || rec.ScanID != snap.ScanID || rec.HostID != snap.HostID {
		return ErrTamper
	}
	return nil
}

func (s Store) VerifyFile(path string) error {
	snap, err := Load(path)
	if err != nil {
		return err
	}
	return s.VerifyTrusted(snap)
}

func Compare(current, approved Snapshot) Diff {
	if approved.Status != StatusTrusted || approved.PayloadHash == "" {
		return Diff{Status: DiffUnknown, Notes: []string{"unapproved or first scan is not an approved baseline and cannot be reported as unchanged"}}
	}
	if current.HostID != approved.HostID {
		return Diff{Status: DiffUnknown, Notes: []string{"baseline host identity does not match the current scan"}}
	}
	diff := Diff{Status: DiffUnchanged}
	if current.Identity != approved.Identity {
		diff.Identity = append(diff.Identity, "host identity changed")
	}
	if !sameStrings(current.sshKeys(), approved.sshKeys()) {
		diff.SSHKeys = append(diff.SSHKeys, "ssh key fingerprints changed")
	}
	if current.sshConfigHash() != approved.sshConfigHash() {
		diff.SSHConfig = append(diff.SSHConfig, "ssh config hash changed")
	}
	if !sameStrings(current.services(), approved.services()) {
		diff.Services = append(diff.Services, "service inventory changed")
	}
	if !sameStrings(current.UID0, approved.UID0) || !sameStrings(current.SUID, approved.SUID) || !sameStrings(current.Cron, approved.Cron) {
		diff.Other = append(diff.Other, "privileged account, suid, or cron inventory changed")
	}
	if len(diff.Identity)+len(diff.SSHKeys)+len(diff.SSHConfig)+len(diff.Services)+len(diff.Other) > 0 {
		diff.Status = DiffChanged
	}
	return diff
}

func (s Store) History(hostID string) ([]Attempt, error) {
	path := filepath.Join(s.hostDir(hostID), "history.jsonl")
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseJSONL[Attempt](payload)
}

func (s Snapshot) sshKeys() []string {
	if len(s.SSHKeys) > 0 {
		return s.SSHKeys
	}
	return s.Fingerprints
}

func (s Snapshot) sshConfigHash() string {
	if s.SSHConfigHash != "" {
		return s.SSHConfigHash
	}
	return s.ConfigHashes["sshd_config"]
}

func (s Snapshot) services() []string {
	if len(s.Services) > 0 {
		return s.Services
	}
	return s.Units
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s Store) appendHistory(hostID string, attempt Attempt) error {
	return appendJSONL(filepath.Join(s.hostDir(hostID), "history.jsonl"), attempt)
}

func (s Store) appendIndex(rec Record) error {
	return appendJSONL(filepath.Join(s.Dir, "index.jsonl"), rec)
}

func (s Store) lastIndex(hostID string) (Record, error) {
	payload, err := os.ReadFile(filepath.Join(s.Dir, "index.jsonl"))
	if err != nil {
		return Record{}, err
	}
	records, err := parseJSONL[Record](payload)
	if err != nil {
		return Record{}, err
	}
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].HostID == hostID {
			return records[i], nil
		}
	}
	return Record{}, ErrTamper
}

func appendJSONL(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		prev, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(prev) == 0 || prev[len(prev)-1] != '\n' {
			return errors.New("jsonl journal is truncated")
		}
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(append(body, '\n'))
	return err
}

func parseJSONL[T any](payload []byte) ([]T, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	if payload[len(payload)-1] != '\n' {
		return nil, errors.New("jsonl journal is truncated")
	}
	var out []T
	start := 0
	for i, b := range payload {
		if b != '\n' {
			continue
		}
		line := payload[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var item T
		if err := json.Unmarshal(line, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
