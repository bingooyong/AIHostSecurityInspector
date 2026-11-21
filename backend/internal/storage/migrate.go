package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

var migrations = []string{
	`-- HOSTSEC-15 evidence metadata slice
CREATE TABLE evidence (
  evidence_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  module TEXT NOT NULL,
  collector_version TEXT NOT NULL,
  category TEXT NOT NULL,
  raw_summary TEXT NOT NULL,
  raw_ref TEXT,
  normalized_data TEXT NOT NULL,
  sha256 TEXT,
  normalized_sha256 TEXT,
  collection_status TEXT NOT NULL,
  integrity_status TEXT NOT NULL,
  completeness TEXT NOT NULL,
  warnings TEXT NOT NULL
);
CREATE TABLE evidence_objects (
  object_id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  view_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id)
);
CREATE UNIQUE INDEX evidence_objects_evidence_view ON evidence_objects(evidence_id, view_type);
`,
	`-- HOSTSEC-15/32 durable append-only audit events
CREATE TABLE audit_events (
  event_id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  host_id TEXT,
  scan_id TEXT,
  plan_id TEXT,
  decision TEXT NOT NULL
);
`,
}

func (d *DB) Migrate(ctx context.Context) error {
	if _, err := d.sql.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return err
	}
	tx, err := d.sql.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL,
		checksum TEXT NOT NULL
	)`); err != nil {
		return err
	}
	var current int
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current)
	if err != nil {
		return err
	}
	if current > len(migrations) {
		return &domain.Error{Code: domain.CodeSchemaVersionUnsupported, Message: "sqlite schema is newer than this binary"}
	}
	for version := current; version < len(migrations); version++ {
		body := migrations[version]
		if version == 0 {
			if _, err := tx.ExecContext(ctx, body); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, body); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(body))
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at, checksum) VALUES(?, datetime('now'), ?)`, version+1, hex.EncodeToString(sum[:])); err != nil {
			return err
		}
	}
	for i, body := range migrations {
		var stored string
		if err := tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version = ?`, i+1).Scan(&stored); err != nil {
			return err
		}
		want := sha256.Sum256([]byte(body))
		if stored != hex.EncodeToString(want[:]) {
			return fmt.Errorf("schema checksum mismatch")
		}
	}
	return tx.Commit()
}
