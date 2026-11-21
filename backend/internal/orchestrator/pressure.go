package orchestrator

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

var ErrResourcePressure = errors.New("resource pressure stop")

// PressureSource reports whether the lab/scheduler should stop remaining modules.
type PressureSource interface {
	Stressed() (bool, string, error)
}

// PSISource reads Linux pressure stall information from Dir (usually /proc/pressure,
// or a fixture directory containing cpu, memory, and io files).
type PSISource struct {
	Dir        string
	Avg10Limit float64
}

func (s PSISource) Stressed() (bool, string, error) {
	if s.Dir == "" {
		return false, "", errors.New("pressure directory is required")
	}
	limit := s.Avg10Limit
	if limit <= 0 {
		limit = 20
	}
	for _, name := range []string{"cpu", "memory", "io"} {
		path := filepath.Join(s.Dir, name)
		avg10, err := readPSIAvg10(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false, "", err
		}
		if avg10 >= limit {
			return true, fmt.Sprintf("%s avg10=%.2f exceeds %.2f", name, avg10, limit), nil
		}
	}
	return false, "", nil
}

func readPSIAvg10(path string) (float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	max := 0.0
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != "some" && fields[0] != "full" {
			continue
		}
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok || key != "avg10" {
				continue
			}
			n, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return 0, err
			}
			if !found || n > max {
				max = n
			}
			found = true
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if !found {
		return 0, errors.New("pressure file has no avg10")
	}
	return max, nil
}

// SequencePressure is a test/lab source that becomes stressed after After successful checks.
type SequencePressure struct {
	After  int
	Reason string
	seen   int
}

func (s *SequencePressure) Stressed() (bool, string, error) {
	s.seen++
	if s.seen > s.After {
		reason := s.Reason
		if reason == "" {
			reason = "injected resource pressure"
		}
		return true, reason, nil
	}
	return false, "", nil
}

func beforeModule(ctx context.Context, source PressureSource, stopOnPressure bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !stopOnPressure || source == nil {
		return nil
	}
	stressed, reason, err := source.Stressed()
	if err != nil {
		return err
	}
	if stressed {
		return fmt.Errorf("%w: %s", ErrResourcePressure, reason)
	}
	return nil
}

func skippedModules(names []string, req Request, cause error) []collector.Result {
	status := domain.CollectionCancelled
	code := "MODULE_CANCELLED"
	warning := "collection_cancelled"
	if errors.Is(cause, context.DeadlineExceeded) {
		status = domain.CollectionTimeout
		code = "MODULE_TIMEOUT"
		warning = "collection_timeout"
	}
	if errors.Is(cause, ErrResourcePressure) {
		status = domain.CollectionCancelled
		code = "RESOURCE_PRESSURE_STOP"
		warning = "resource_pressure_stop"
	}
	started := time.Now().UTC()
	if req.Now != nil {
		started = req.Now().UTC()
	}
	out := make([]collector.Result, 0, len(names))
	for _, name := range names {
		out = append(out, collector.Result{
			ModuleID: name, Version: collector.Version, StartedAt: started.Format(domain.TimeLayout),
			Status: status, Completeness: domain.CompletenessUnavailable,
			Records: []map[string]any{}, RawRefs: []string{}, Warnings: []string{warning},
			ErrorCode: code,
		})
	}
	return out
}
