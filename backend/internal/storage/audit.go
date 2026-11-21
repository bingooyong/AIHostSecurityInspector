package storage

import (
	"context"
	"database/sql"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

type AuditRow struct {
	EventID  string
	At       string
	Actor    string
	Action   string
	HostID   string
	ScanID   string
	PlanID   string
	Decision string
}

func (d *DB) AppendAudit(ctx context.Context, row AuditRow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !domain.ValidEntityID(row.EventID) || row.At == "" || row.Actor == "" || row.Action == "" || row.Decision == "" {
		return &domain.Error{Code: domain.CodeInvalidCanonical, Message: "audit event is invalid"}
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO audit_events(event_id, at, actor, action, host_id, scan_id, plan_id, decision) VALUES(?,?,?,?,?,?,?,?)`,
		row.EventID, row.At, row.Actor, row.Action, row.HostID, row.ScanID, row.PlanID, row.Decision)
	return err
}

func (d *DB) ListAudit(ctx context.Context) ([]AuditRow, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT event_id, at, actor, action, host_id, scan_id, plan_id, decision FROM audit_events ORDER BY at, event_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]AuditRow, 0)
	for rows.Next() {
		var row AuditRow
		var host, scan, plan sql.NullString
		if err := rows.Scan(&row.EventID, &row.At, &row.Actor, &row.Action, &host, &scan, &plan, &row.Decision); err != nil {
			return nil, err
		}
		row.HostID, row.ScanID, row.PlanID = host.String, scan.String, plan.String
		out = append(out, row)
	}
	return out, rows.Err()
}
