package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/storage"
)

const ManifestSchema = "manifest-v1"

type Manifest struct {
	SchemaVersion    string          `json:"schema_version"`
	ScanID           string          `json:"scan_id"`
	HostIDs          []string        `json:"host_ids"`
	AttemptIDs       []string        `json:"attempt_ids"`
	CreatedAt        string          `json:"created_at"`
	Producer         string          `json:"producer"`
	CollectorVersion string          `json:"collector_version"`
	PolicyVersion    string          `json:"policy_version"`
	Signature        *string         `json:"signature"`
	SignatureNote    string          `json:"signature_note"`
	Entries          []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	ObjectID   string `json:"object_id"`
	Relative   string `json:"relative_path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	MediaType  string `json:"media_type"`
	EvidenceID string `json:"evidence_id"`
	ViewType   string `json:"view_type"`
}

type VerificationReport struct {
	OK                 bool     `json:"ok"`
	Integrity          string   `json:"integrity"`
	SourceAuthenticity string   `json:"source_authenticity"`
	Mismatches         []string `json:"mismatches"`
	Missing            []string `json:"missing"`
	Extra              []string `json:"extra"`
}

func (s *Store) BuildManifest(ctx context.Context, scanID, policyVersion string) (Manifest, error) {
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if !domain.ValidEntityID(scanID) {
		return Manifest{}, &domain.Error{Code: domain.CodeInvalidID, Message: "scan_id is invalid"}
	}
	rows, err := s.db.ListObjects(ctx)
	if err != nil {
		return Manifest{}, err
	}
	items, err := s.db.ListEvidence(ctx, scanID)
	if err != nil {
		return Manifest{}, err
	}
	byEvidence := map[string]domain.Evidence{}
	hosts := map[string]struct{}{}
	attempts := map[string]struct{}{}
	for _, ev := range items {
		byEvidence[ev.EvidenceID] = ev
		hosts[ev.HostID] = struct{}{}
		attempts[ev.AttemptID] = struct{}{}
	}
	entries := make([]ManifestEntry, 0)
	for _, row := range rows {
		ev, ok := byEvidence[row.EvidenceID]
		if !ok {
			continue
		}
		media := "application/octet-stream"
		if row.ViewType == "normalized" {
			media = "application/json"
		}
		entries = append(entries, ManifestEntry{
			ObjectID: row.ObjectID, Relative: filepath.Join("objects", row.ObjectID),
			Size: row.Size, SHA256: row.SHA256, MediaType: media,
			EvidenceID: ev.EvidenceID, ViewType: row.ViewType,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ObjectID < entries[j].ObjectID })
	man := Manifest{
		SchemaVersion: ManifestSchema, ScanID: scanID,
		HostIDs: sortedKeys(hosts), AttemptIDs: sortedKeys(attempts),
		CreatedAt: s.now().UTC().Format(domain.TimeLayout), Producer: "hostsec-evidence-store",
		CollectorVersion: collectorVersion(items), PolicyVersion: policyVersion,
		Signature: nil, SignatureNote: "hash proves object bytes match this manifest only; not host source authenticity",
		Entries: entries,
	}
	payload, err := json.Marshal(man)
	if err != nil {
		return Manifest{}, err
	}
	path := filepath.Join(s.root, "manifest.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return Manifest{}, storage.ClassifyIO(err)
	}
	return man, nil
}

func (s *Store) LoadManifest() (Manifest, error) {
	payload, err := os.ReadFile(filepath.Join(s.root, "manifest.json"))
	if err != nil {
		return Manifest{}, storage.ClassifyIO(err)
	}
	var man Manifest
	if err := json.Unmarshal(payload, &man); err != nil {
		return Manifest{}, err
	}
	return man, nil
}

func (s *Store) Verify(ctx context.Context, scanID string) (VerificationReport, error) {
	report := VerificationReport{
		Integrity: domain.IntegrityFailed, SourceAuthenticity: "unverified",
		Mismatches: []string{}, Missing: []string{}, Extra: []string{},
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	man, err := s.LoadManifest()
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(s.root, "manifest.json")); statErr == nil {
			// A present but unreadable/corrupt manifest must not be rebuilt into a passing report.
			report.Mismatches = append(report.Mismatches, "manifest")
			return report, err
		}
		man, err = s.BuildManifest(ctx, scanID, "0.1.0")
		if err != nil {
			return report, err
		}
	}
	if man.ScanID != scanID {
		report.Mismatches = append(report.Mismatches, "scan_id")
		return report, nil
	}
	seen := map[string]struct{}{}
	for _, entry := range man.Entries {
		seen[entry.ObjectID] = struct{}{}
		path, pathErr := s.objectPath(entry.ObjectID)
		if pathErr != nil {
			report.Missing = append(report.Missing, entry.ObjectID)
			continue
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			report.Missing = append(report.Missing, entry.ObjectID)
			_ = s.db.MarkIntegrityFailed(ctx, entry.EvidenceID)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			report.Mismatches = append(report.Mismatches, entry.ObjectID)
			_ = s.db.MarkIntegrityFailed(ctx, entry.EvidenceID)
			continue
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			report.Missing = append(report.Missing, entry.ObjectID)
			continue
		}
		sum := sha256.New()
		n, copyErr := io.Copy(sum, file)
		_ = file.Close()
		if copyErr != nil {
			report.Mismatches = append(report.Mismatches, entry.ObjectID)
			continue
		}
		digest := hex.EncodeToString(sum.Sum(nil))
		if n != entry.Size || digest != entry.SHA256 {
			report.Mismatches = append(report.Mismatches, entry.ObjectID)
			_ = s.db.MarkIntegrityFailed(ctx, entry.EvidenceID)
			continue
		}
		_ = s.db.MarkIntegrity(ctx, entry.EvidenceID, domain.IntegrityVerified)
	}
	entries, _ := os.ReadDir(filepath.Join(s.root, objectsDir))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := seen[entry.Name()]; !ok {
			report.Extra = append(report.Extra, entry.Name())
		}
	}
	if len(report.Mismatches) == 0 && len(report.Missing) == 0 && len(report.Extra) == 0 {
		report.OK = true
		report.Integrity = domain.IntegrityVerified
	}
	return report, nil
}

func collectorVersion(items []domain.Evidence) string {
	if len(items) == 0 {
		return "0.1.0"
	}
	return items[0].CollectorVersion
}

func sortedKeys(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
