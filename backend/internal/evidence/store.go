package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/storage"
)

const (
	objectsDir = "objects"
	tmpDir     = "tmp"
	orphanDir  = "orphans"
)

type Store struct {
	root string
	now  func() time.Time
	db   *storage.DB
}

type Input struct {
	EvidenceID       string
	HostID           string
	ScanID           string
	AttemptID        string
	CollectedAt      time.Time
	Module           string
	CollectorVersion string
	Category         string
	RawSummary       string
	CollectionStatus string
	Completeness     string
	Warnings         []string
	Raw              []byte
	Normalized       map[string]any
}

type RecoveryReport struct {
	Quarantined    []string
	MissingObjects []string
}

func Open(ctx context.Context, root string, now func() time.Time) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) == "/" {
		return nil, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "evidence root is invalid"}
	}
	if now == nil {
		now = time.Now
	}
	for _, name := range []string{objectsDir, tmpDir, orphanDir} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, storage.ClassifyIO(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, err
		}
	}
	db, err := storage.Open(ctx, filepath.Join(root, "hostsec.sqlite"))
	if err != nil {
		return nil, err
	}
	store := &Store{root: root, now: now, db: db}
	if _, err := store.Recover(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Put(ctx context.Context, in Input) (domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return domain.Evidence{}, err
	}
	if err := validateInput(in); err != nil {
		return domain.Evidence{}, err
	}
	received := s.now().UTC()
	if received.Before(in.CollectedAt.UTC()) {
		received = in.CollectedAt.UTC()
	}
	normalized, err := json.Marshal(in.Normalized)
	if err != nil {
		return domain.Evidence{}, err
	}
	objects := make([]storage.ObjectRow, 0, 2)
	ev := domain.Evidence{
		EvidenceID:       in.EvidenceID,
		HostID:           in.HostID,
		ScanID:           in.ScanID,
		AttemptID:        in.AttemptID,
		CollectedAt:      in.CollectedAt.UTC().Format(domain.TimeLayout),
		ReceivedAt:       received.Format(domain.TimeLayout),
		Module:           in.Module,
		CollectorVersion: in.CollectorVersion,
		Category:         in.Category,
		RawSummary:       in.RawSummary,
		NormalizedData:   in.Normalized,
		CollectionStatus: in.CollectionStatus,
		IntegrityStatus:  domain.IntegrityUnverified,
		Completeness:     in.Completeness,
		Warnings:         storage.NormalizeWarnings(in.Warnings),
	}
	if in.Raw != nil {
		object, err := s.writeObject(ctx, "raw."+in.EvidenceID, in.Raw)
		if err != nil {
			return domain.Evidence{}, err
		}
		ev.RawRef = &object.ObjectID
		ev.SHA256 = &object.SHA256
		objects = append(objects, object)
	}
	if in.Normalized != nil {
		object, err := s.writeObject(ctx, "norm."+in.EvidenceID, normalized)
		if err != nil {
			return domain.Evidence{}, err
		}
		ev.NormalizedSHA256 = &object.SHA256
		objects = append(objects, object)
	}
	if err := s.db.InsertEvidence(ctx, ev, objects); err != nil {
		return domain.Evidence{}, err
	}
	return ev, nil
}

func (s *Store) GetMetadata(ctx context.Context, evidenceID string) (domain.Evidence, error) {
	return s.db.GetEvidence(ctx, evidenceID)
}

func (s *Store) List(ctx context.Context, scanID string) ([]domain.Evidence, error) {
	return s.db.ListEvidence(ctx, scanID)
}

func (s *Store) OpenRaw(ctx context.Context, evidenceID string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	object, err := s.db.Object(ctx, evidenceID, "raw")
	if err != nil {
		return nil, err
	}
	path, err := s.objectPath(object.ObjectID)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &domain.Error{Code: domain.CodeInvalidReference, Message: "evidence object is a symlink"}
	}
	return os.Open(path)
}

func (s *Store) Recover(ctx context.Context) (RecoveryReport, error) {
	report := RecoveryReport{Quarantined: []string{}, MissingObjects: []string{}}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	known := map[string]storage.ObjectRow{}
	rows, err := s.db.ListObjects(ctx)
	if err != nil {
		return report, err
	}
	for _, row := range rows {
		known[row.ObjectID] = row
		path, pathErr := s.objectPath(row.ObjectID)
		if pathErr != nil {
			report.MissingObjects = append(report.MissingObjects, row.ObjectID)
			_ = s.db.MarkIntegrityFailed(ctx, row.EvidenceID)
			continue
		}
		if _, statErr := os.Lstat(path); statErr != nil {
			report.MissingObjects = append(report.MissingObjects, row.ObjectID)
			_ = s.db.MarkIntegrityFailed(ctx, row.EvidenceID)
		}
	}
	if err := s.quarantineDir(tmpDir, &report); err != nil {
		return report, err
	}
	entries, err := os.ReadDir(filepath.Join(s.root, objectsDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return report, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := known[entry.Name()]; ok {
			continue
		}
		if err := s.quarantine(filepath.Join(s.root, objectsDir, entry.Name()), &report); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (s *Store) writeObject(ctx context.Context, objectID string, payload []byte) (storage.ObjectRow, error) {
	if err := ctx.Err(); err != nil {
		return storage.ObjectRow{}, err
	}
	path, err := s.objectPath(objectID)
	if err != nil {
		return storage.ObjectRow{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return storage.ObjectRow{}, storage.ErrAppendOnly
	}
	tmp, err := os.OpenFile(filepath.Join(s.root, tmpDir, objectID+".partial"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return storage.ObjectRow{}, classifyWrite(err)
	}
	sum := sha256.New()
	writer := io.MultiWriter(tmp, sum)
	if _, err := writer.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return storage.ObjectRow{}, classifyWrite(err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return storage.ObjectRow{}, classifyWrite(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return storage.ObjectRow{}, classifyWrite(err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		_ = os.Remove(tmp.Name())
		return storage.ObjectRow{}, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return storage.ObjectRow{}, classifyWrite(err)
	}
	digest := hex.EncodeToString(sum.Sum(nil))
	viewType := "raw"
	if strings.HasPrefix(objectID, "norm.") {
		viewType = "normalized"
	}
	return storage.ObjectRow{ObjectID: objectID, ViewType: viewType, Size: int64(len(payload)), SHA256: digest}, nil
}

func (s *Store) objectPath(objectID string) (string, error) {
	if !domain.ValidEntityID(objectID) || strings.Contains(objectID, "/") || strings.Contains(objectID, `\`) || strings.Contains(objectID, "..") {
		return "", &domain.Error{Code: domain.CodeInvalidID, Message: "object id is invalid"}
	}
	return filepath.Join(s.root, objectsDir, objectID), nil
}

func (s *Store) quarantineDir(name string, report *RecoveryReport) error {
	entries, err := os.ReadDir(filepath.Join(s.root, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := s.quarantine(filepath.Join(s.root, name, entry.Name()), report); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) quarantine(path string, report *RecoveryReport) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	target := filepath.Join(s.root, orphanDir, filepath.Base(path))
	if err := os.Rename(path, target); err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		_ = os.Chmod(target, 0o600)
	}
	report.Quarantined = append(report.Quarantined, filepath.Base(path))
	return nil
}

func validateInput(in Input) error {
	if !domain.ValidEntityID(in.EvidenceID) || !domain.ValidHostID(in.HostID) || !domain.ValidEntityID(in.ScanID) || !domain.ValidEntityID(in.AttemptID) {
		return &domain.Error{Code: domain.CodeInvalidID, Message: "evidence identity is invalid"}
	}
	if !domain.ValidEntityID(in.Module) || !domain.ValidVersion(in.CollectorVersion) || !domain.ValidEntityID(in.Category) {
		return &domain.Error{Code: domain.CodeInvalidID, Message: "evidence module fields are invalid"}
	}
	if !domain.ValidCollectionStatus(in.CollectionStatus) || !domain.ValidCompleteness(in.Completeness) {
		return &domain.Error{Code: domain.CodeInvalidEnum, Message: "evidence status enum is invalid"}
	}
	if in.Normalized == nil {
		return &domain.Error{Code: domain.CodeInvalidCanonical, Message: "normalized_data is required"}
	}
	if in.CollectionStatus == domain.CollectionSuccess && len(in.Raw) == 0 {
		return &domain.Error{Code: domain.CodeInvalidCanonical, Message: "successful collection requires raw bytes"}
	}
	return nil
}

func classifyWrite(err error) error {
	if classified := storage.ClassifyIO(err); classified != nil {
		return classified
	}
	return err
}
