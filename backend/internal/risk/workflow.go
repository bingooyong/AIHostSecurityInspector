package risk

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const (
	StateOpen          = "open"
	StateFalsePositive = "false_positive"
	StateRemediated    = "remediated"
	StateVerified      = "verified"
	StateReopened      = "reopened"
)

var (
	ErrHostDrift    = errors.New("host identity drifted; case cannot close across hosts")
	ErrAutoTraining = errors.New("automatic training or disposal is not permitted")
	ErrInvalidState = errors.New("case state transition is invalid")
	ErrCaseNotFound = errors.New("risk case is unknown")
	ErrClosedLoop   = errors.New("rescan is required before a case can be verified")
)

type Event struct {
	At     string `json:"at"`
	Action string `json:"action"`
	ScanID string `json:"scan_id"`
	State  string `json:"state"`
	Note   string `json:"note,omitempty"`
}

type Case struct {
	CaseID      string   `json:"case_id"`
	FindingID   string   `json:"finding_id"`
	RuleID      string   `json:"rule_id"`
	HostID      string   `json:"host_id"`
	OpenedScan  string   `json:"opened_scan_id"`
	State       string   `json:"state"`
	LinkedScans []string `json:"linked_scans"`
	History     []Event  `json:"history"`
}

type Store struct {
	mu    sync.Mutex
	dir   string
	items map[string]Case
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	store := &Store{dir: dir, items: map[string]Case{}}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) OpenCase(finding domain.Finding, now time.Time) (Case, error) {
	if !domain.ValidEntityID(finding.FindingID) || !domain.ValidHostID(finding.HostID) || !domain.ValidEntityID(finding.ScanID) || !domain.ValidEntityID(finding.RuleID) {
		return Case{}, &domain.Error{Code: domain.CodeInvalidID, Message: "finding identifiers are invalid"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := "case-" + finding.RuleID + "-" + finding.HostID
	if existing, ok := s.items[id]; ok {
		return existing, nil
	}
	cs := Case{
		CaseID: id, FindingID: finding.FindingID, RuleID: finding.RuleID, HostID: finding.HostID,
		OpenedScan: finding.ScanID, State: StateOpen, LinkedScans: []string{finding.ScanID},
		History: []Event{{At: now.UTC().Format(domain.TimeLayout), Action: "open", ScanID: finding.ScanID, State: StateOpen}},
	}
	if err := s.saveLocked(cs); err != nil {
		return Case{}, err
	}
	return cs, nil
}

func (s *Store) RecordFalsePositive(caseID, actor, scanID string, now time.Time) (Case, error) {
	return s.transition(caseID, StateFalsePositive, "false_positive", scanID, actor, now, nil)
}

func (s *Store) RecordRemediation(caseID, actor, scanID, note string, now time.Time) (Case, error) {
	if note == "auto" || note == "train" || actor == "auto" {
		return Case{}, ErrAutoTraining
	}
	return s.transition(caseID, StateRemediated, "remediation", scanID, note, now, nil)
}

func (s *Store) LinkRescan(caseID, scanID, hostID string, stillPresent bool, now time.Time) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.items[caseID]
	if !ok {
		return Case{}, ErrCaseNotFound
	}
	if hostID != cs.HostID {
		return Case{}, ErrHostDrift
	}
	if !domain.ValidEntityID(scanID) {
		return Case{}, &domain.Error{Code: domain.CodeInvalidID, Message: "rescan id is invalid"}
	}
	next := StateReopened
	action := "rescan_reopened"
	if !stillPresent {
		if cs.State != StateRemediated && cs.State != StateFalsePositive && cs.State != StateVerified {
			return Case{}, ErrClosedLoop
		}
		next = StateVerified
		action = "rescan_verified"
	}
	cs.State = next
	cs.LinkedScans = append(cs.LinkedScans, scanID)
	cs.History = append(cs.History, Event{At: now.UTC().Format(domain.TimeLayout), Action: action, ScanID: scanID, State: next})
	if err := s.saveLocked(cs); err != nil {
		return Case{}, err
	}
	return cs, nil
}

func (s *Store) Timeline(caseID string) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.items[caseID]
	if !ok {
		return nil, ErrCaseNotFound
	}
	out := make([]Event, len(cs.History))
	copy(out, cs.History)
	return out, nil
}

func (s *Store) Get(caseID string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.items[caseID]
	if !ok {
		return Case{}, ErrCaseNotFound
	}
	return cs, nil
}

func (s *Store) transition(caseID, next, action, scanID, note string, now time.Time, check func(Case) error) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.items[caseID]
	if !ok {
		return Case{}, ErrCaseNotFound
	}
	if check != nil {
		if err := check(cs); err != nil {
			return Case{}, err
		}
	}
	if next == StateFalsePositive && cs.State == StateVerified {
		return Case{}, ErrInvalidState
	}
	cs.State = next
	if scanID != "" {
		cs.LinkedScans = append(cs.LinkedScans, scanID)
	}
	cs.History = append(cs.History, Event{At: now.UTC().Format(domain.TimeLayout), Action: action, ScanID: scanID, State: next, Note: note})
	if err := s.saveLocked(cs); err != nil {
		return Case{}, err
	}
	return cs, nil
}

func (s *Store) saveLocked(cs Case) error {
	s.items[cs.CaseID] = cs
	payload, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, cs.CaseID+".json"), append(payload, '\n'), 0o600)
}

func (s *Store) load() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return err
		}
		var cs Case
		if err := json.Unmarshal(payload, &cs); err != nil {
			return err
		}
		s.items[cs.CaseID] = cs
	}
	return nil
}

// Series compares findings across an ordered list of scans on one host.
func Series(hostID string, scans [][]domain.Finding) ([]Change, error) {
	if len(scans) == 0 {
		return nil, nil
	}
	var previous []domain.Finding
	var out []Change
	for i, current := range scans {
		for _, finding := range current {
			if finding.HostID != hostID {
				return nil, ErrHostDrift
			}
		}
		changes, err := Trend(previous, current, i == 0)
		if err != nil {
			return nil, err
		}
		out = append(out, changes...)
		previous = current
	}
	return out, nil
}
