package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"

	_ "modernc.org/sqlite"
)

const (
	driverName  = "sqlite"
	busyTimeout = 5000
)

var (
	ErrDiskFull   = errors.New("evidence disk is full")
	ErrAppendOnly = errors.New("evidence objects are append-only")
)

type DB struct {
	sql  *sql.DB
	path string
}

func Open(ctx context.Context, path string) (*DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" || path == ":memory:" {
		return nil, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "sqlite path is required"}
	}
	if !filepath.IsAbs(path) {
		return nil, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "sqlite path must be absolute"}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, classifyIO(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
		return nil, classifyIO(err)
	}
	handle, err := sql.Open(driverName, fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)", filepath.ToSlash(path), busyTimeout))
	if err != nil {
		return nil, err
	}
	handle.SetMaxOpenConns(1)
	handle.SetMaxIdleConns(1)
	if err := handle.PingContext(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = handle.Close()
		return nil, classifyIO(err)
	}
	db := &DB{sql: handle, path: path}
	if err := db.Migrate(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return db, nil
}

func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

func (d *DB) SQL() *sql.DB {
	return d.sql
}

func ClassifyIO(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ENOSPC) {
		return ErrDiskFull
	}
	return err
}

func classifyIO(err error) error { return ClassifyIO(err) }
