package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

type ObjectRow struct {
	ObjectID   string
	EvidenceID string
	ViewType   string
	Size       int64
	SHA256     string
}

func (d *DB) InsertEvidence(ctx context.Context, ev domain.Evidence, objects []ObjectRow) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	normalized, err := json.Marshal(ev.NormalizedData)
	if err != nil {
		return err
	}
	warnings, err := json.Marshal(ev.Warnings)
	if err != nil {
		return err
	}
	tx, err := d.sql.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT evidence_id FROM evidence WHERE evidence_id = ?`, ev.EvidenceID).Scan(&existing)
	if err == nil {
		return &domain.Error{Code: domain.CodeDuplicateID, Message: "evidence id already exists"}
	}
	if err != sql.ErrNoRows {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO evidence(
		evidence_id, host_id, scan_id, attempt_id, collected_at, received_at, module, collector_version, category,
		raw_summary, raw_ref, normalized_data, sha256, normalized_sha256, collection_status, integrity_status, completeness, warnings
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.EvidenceID, ev.HostID, ev.ScanID, ev.AttemptID, ev.CollectedAt, ev.ReceivedAt, ev.Module, ev.CollectorVersion, ev.Category,
		ev.RawSummary, ev.RawRef, string(normalized), ev.SHA256, ev.NormalizedSHA256, ev.CollectionStatus, ev.IntegrityStatus, ev.Completeness, string(warnings),
	)
	if err != nil {
		return err
	}
	for _, object := range objects {
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_objects(object_id, evidence_id, view_type, size, sha256) VALUES(?,?,?,?,?)`,
			object.ObjectID, ev.EvidenceID, object.ViewType, object.Size, object.SHA256); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) GetEvidence(ctx context.Context, evidenceID string) (domain.Evidence, error) {
	row := d.sql.QueryRowContext(ctx, `SELECT evidence_id, host_id, scan_id, attempt_id, collected_at, received_at, module, collector_version, category,
		raw_summary, raw_ref, normalized_data, sha256, normalized_sha256, collection_status, integrity_status, completeness, warnings
		FROM evidence WHERE evidence_id = ?`, evidenceID)
	var ev domain.Evidence
	var rawRef, sha, nsha sql.NullString
	var normalized, warnings string
	err := row.Scan(&ev.EvidenceID, &ev.HostID, &ev.ScanID, &ev.AttemptID, &ev.CollectedAt, &ev.ReceivedAt, &ev.Module, &ev.CollectorVersion, &ev.Category,
		&ev.RawSummary, &rawRef, &normalized, &sha, &nsha, &ev.CollectionStatus, &ev.IntegrityStatus, &ev.Completeness, &warnings)
	if err == sql.ErrNoRows {
		return domain.Evidence{}, &domain.Error{Code: domain.CodeUnknownEvidence, Message: "evidence is unknown"}
	}
	if err != nil {
		return domain.Evidence{}, err
	}
	if rawRef.Valid {
		ev.RawRef = &rawRef.String
	}
	if sha.Valid {
		ev.SHA256 = &sha.String
	}
	if nsha.Valid {
		ev.NormalizedSHA256 = &nsha.String
	}
	if err := json.Unmarshal([]byte(normalized), &ev.NormalizedData); err != nil {
		return domain.Evidence{}, err
	}
	if err := json.Unmarshal([]byte(warnings), &ev.Warnings); err != nil {
		return domain.Evidence{}, err
	}
	return ev, ev.Validate()
}

func (d *DB) ListObjects(ctx context.Context) ([]ObjectRow, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT object_id, evidence_id, view_type, size, sha256 FROM evidence_objects`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]ObjectRow, 0)
	for rows.Next() {
		var row ObjectRow
		if err := rows.Scan(&row.ObjectID, &row.EvidenceID, &row.ViewType, &row.Size, &row.SHA256); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (d *DB) Object(ctx context.Context, evidenceID, viewType string) (ObjectRow, error) {
	var row ObjectRow
	err := d.sql.QueryRowContext(ctx, `SELECT object_id, evidence_id, view_type, size, sha256 FROM evidence_objects WHERE evidence_id = ? AND view_type = ?`, evidenceID, viewType).
		Scan(&row.ObjectID, &row.EvidenceID, &row.ViewType, &row.Size, &row.SHA256)
	if err == sql.ErrNoRows {
		return ObjectRow{}, &domain.Error{Code: domain.CodeUnknownEvidence, Message: "evidence object is unknown"}
	}
	return row, err
}

func (d *DB) MarkIntegrityFailed(ctx context.Context, evidenceID string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE evidence SET integrity_status = ? WHERE evidence_id = ?`, domain.IntegrityFailed, evidenceID)
	return err
}

func NormalizeWarnings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
