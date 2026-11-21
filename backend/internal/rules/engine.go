package rules

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v4"
	"go.yaml.in/yaml/v4/plugin/loaderlimits"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/baseline"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/findings"
)

//go:embed bundle.yaml
var DefaultBundle []byte

type Bundle struct {
	BundleID string `yaml:"bundle_id"`
	Version  string `yaml:"version"`
	Platform string `yaml:"platform"`
	Rules    []Rule `yaml:"rules"`
}

type Rule struct {
	RuleID              string   `yaml:"rule_id"`
	Version             string   `yaml:"version"`
	Title               string   `yaml:"title"`
	Category            string   `yaml:"category"`
	Platform            string   `yaml:"platform"`
	Profiles            []string `yaml:"profiles"`
	Severity            string   `yaml:"severity"`
	Confidence          int      `yaml:"confidence"`
	RequiredEvidence    []string `yaml:"required_evidence"`
	DetectionLogic      Logic    `yaml:"detection_logic"`
	FalsePositiveNotes  string   `yaml:"false_positive_notes"`
	RemediationGuidance []string `yaml:"remediation_guidance"`
	References          []string `yaml:"references"`
}

type Logic struct {
	Predicate string `yaml:"predicate"`
	Field     string `yaml:"field,omitempty"`
}

var allowedPredicates = map[string]bool{
	"is_deleted_executable": true, "path_under": true, "listen_not_in_baseline": true,
	"uid0_not_in_baseline": true, "unit_not_in_baseline": true, "cron_not_in_baseline": true,
	"fingerprint_baseline_diff": true, "suid_not_in_baseline": true, "config_hash_baseline_diff": true,
}

func Load(payload []byte) (Bundle, error) {
	opts := []yaml.Option{yaml.WithKnownFields(), yaml.WithUniqueKeys(), yaml.WithPlugin(loaderlimits.New(loaderlimits.DepthValue(8), loaderlimits.AliasNone()))}
	var node yaml.Node
	if err := yaml.Load(payload, &node, opts...); err != nil {
		return Bundle{}, err
	}
	var bundle Bundle
	if err := node.Load(&bundle, opts...); err != nil {
		return Bundle{}, err
	}
	if bundle.BundleID == "" || !domain.ValidVersion(bundle.Version) || len(bundle.Rules) == 0 {
		return Bundle{}, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "rule bundle is invalid"}
	}
	seen := map[string]struct{}{}
	for _, rule := range bundle.Rules {
		if !domain.ValidEntityID(rule.RuleID) || !domain.ValidVersion(rule.Version) || !allowedPredicates[rule.DetectionLogic.Predicate] {
			return Bundle{}, &domain.Error{Code: domain.CodeInvalidCanonical, Message: "rule is invalid"}
		}
		if _, ok := seen[rule.RuleID]; ok {
			return Bundle{}, &domain.Error{Code: domain.CodeDuplicateID, Message: "duplicate rule_id"}
		}
		seen[rule.RuleID] = struct{}{}
	}
	return bundle, nil
}

func Meta(bundle Bundle) map[string]findings.RuleMeta {
	out := map[string]findings.RuleMeta{}
	for _, rule := range bundle.Rules {
		out[rule.RuleID] = findings.RuleMeta{
			Category: rule.Category, Severity: rule.Severity, Confidence: rule.Confidence,
			Title: rule.Title, Description: rule.Title, Remediation: append([]string{}, rule.RemediationGuidance...),
		}
	}
	return out
}

func Evaluate(ctx context.Context, scanID, hostID, profile string, evidence []domain.Evidence, base baseline.Snapshot, bundle Bundle) ([]domain.RuleResult, []domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	byModule := map[string]domain.Evidence{}
	index := map[string]domain.Evidence{}
	for _, ev := range evidence {
		index[ev.EvidenceID] = ev
		byModule[ev.Module] = ev
	}
	results := make([]domain.RuleResult, 0, len(bundle.Rules))
	for _, rule := range bundle.Rules {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		results = append(results, evaluateRule(rule, scanID, hostID, profile, byModule, base))
	}
	findingsOut, err := findings.FromRuleResults(results, index, Meta(bundle))
	if err != nil {
		return nil, nil, err
	}
	return results, findingsOut, nil
}

func evaluateRule(rule Rule, scanID, hostID, profile string, byModule map[string]domain.Evidence, base baseline.Snapshot) domain.RuleResult {
	result := domain.RuleResult{
		RuleID: rule.RuleID, RuleVersion: rule.Version, ScanID: scanID, HostID: hostID,
		EvidenceRefs: []string{}, MissingEvidence: []string{},
	}
	if profile != "" && !contains(rule.Profiles, profile) {
		result.Outcome = domain.OutcomeNotApplicable
		result.ReasonCode = "profile_not_applicable"
		return result
	}
	var usable []domain.Evidence
	for _, module := range rule.RequiredEvidence {
		ev, ok := byModule[module]
		if !ok {
			result.MissingEvidence = append(result.MissingEvidence, module)
			continue
		}
		result.EvidenceRefs = append(result.EvidenceRefs, ev.EvidenceID)
		if ev.HostID != result.HostID || ev.ScanID != result.ScanID {
			result.Outcome = domain.OutcomeUnknown
			result.ReasonCode = "cross_scope_evidence"
			return result
		}
		usable = append(usable, ev)
	}
	if len(result.MissingEvidence) > 0 {
		result.Outcome = domain.OutcomeUnknown
		result.ReasonCode = "missing_evidence"
		return result
	}
	for _, ev := range usable {
		if ev.CollectionStatus == domain.CollectionNotApplicable {
			result.Outcome = domain.OutcomeNotApplicable
			result.ReasonCode = "collection_not_applicable"
			return result
		}
		if !ev.SupportsDetection() {
			if hit, ok := anomalyPresent(rule, ev, base); ok && hit && ev.SupportsCollectionFailure() && ev.CollectionStatus == domain.CollectionPartial {
				result.Outcome = domain.OutcomeUnknown
				result.ReasonCode = "partial_not_enough_for_fail"
				return result
			}
			result.Outcome = domain.OutcomeUnknown
			result.ReasonCode = "evidence_unusable"
			return result
		}
	}
	needsBaseline := strings.Contains(rule.DetectionLogic.Predicate, "baseline")
	if needsBaseline && !base.Trusted() {
		result.Outcome = domain.OutcomeUnknown
		result.ReasonCode = "missing_trusted_baseline"
		result.MissingEvidence = []string{"trusted_baseline"}
		result.EvidenceRefs = []string{}
		return result
	}
	if needsBaseline {
		ref := base.ScanID
		result.BaselineRef = &ref
	}
	hit, reason := apply(rule, usable[0], base)
	if hit {
		result.Outcome = domain.OutcomeFail
		result.ReasonCode = reason
		return result
	}
	result.Outcome = domain.OutcomePass
	result.ReasonCode = "condition_not_met"
	return result
}

func anomalyPresent(rule Rule, ev domain.Evidence, base baseline.Snapshot) (bool, bool) {
	hit, _ := apply(rule, ev, base)
	return hit, true
}

func apply(rule Rule, ev domain.Evidence, base baseline.Snapshot) (bool, string) {
	switch rule.DetectionLogic.Predicate {
	case "is_deleted_executable":
		return anyRecord(ev, func(rec map[string]any) bool {
			return rec["kernel_thread"] != true && rec["exe_reason"] == "deleted"
		}), "deleted_executable"
	case "path_under":
		return anyRecord(ev, func(rec map[string]any) bool {
			path, _ := rec["exe_path"].(string)
			return pathUnder(path, base.SuspiciousDirs)
		}), "suspicious_path"
	case "listen_not_in_baseline":
		return anySocket(ev, func(sock map[string]any) bool {
			if sock["listening"] != true {
				return false
			}
			key := fmt.Sprintf("%s/%v", sock["protocol"], sock["local_address"])
			return !contains(base.ListenAllow, key)
		}), "unapproved_listener"
	case "uid0_not_in_baseline":
		values := stringSlice(ev.NormalizedData["uid0"])
		for _, name := range values {
			if !contains(base.UID0, name) {
				return true, "unapproved_uid0"
			}
		}
		return false, "unapproved_uid0"
	case "unit_not_in_baseline":
		return anyNamed(ev, "units", base.Units), "unapproved_unit"
	case "cron_not_in_baseline":
		return anyNamed(ev, "cron", base.Cron), "unapproved_cron"
	case "fingerprint_baseline_diff":
		current := fingerprints(ev)
		return !sameSet(current, base.Fingerprints), "ssh_key_changed"
	case "suid_not_in_baseline":
		return anyRecord(ev, func(rec map[string]any) bool {
			if rec["suid"] != true && rec["sgid"] != true {
				return false
			}
			path, _ := rec["path"].(string)
			return !contains(base.SUID, path)
		}), "unapproved_suid"
	case "config_hash_baseline_diff":
		ssh, _ := ev.NormalizedData["ssh"].(map[string]any)
		if ssh == nil {
			return false, "config_changed"
		}
		current := fmt.Sprintf("%v|%v|%v", ssh["permit_root_login"], ssh["password_authentication"], ssh["include_unresolved"])
		want := base.ConfigHashes["ssh"]
		return want != "" && current != want, "config_changed"
	}
	return false, "unknown_predicate"
}

func anyRecord(ev domain.Evidence, match func(map[string]any) bool) bool {
	records, _ := ev.NormalizedData["records"].([]any)
	if records == nil {
		if match(ev.NormalizedData) {
			return true
		}
		for _, rec := range asRecords(ev) {
			if match(rec) {
				return true
			}
		}
		return false
	}
	for _, item := range records {
		rec, _ := item.(map[string]any)
		if rec != nil && match(rec) {
			return true
		}
	}
	return false
}

func asRecords(ev domain.Evidence) []map[string]any {
	if recs, ok := ev.NormalizedData["records"].([]any); ok {
		out := make([]map[string]any, 0, len(recs))
		for _, item := range recs {
			if rec, ok := item.(map[string]any); ok {
				out = append(out, rec)
			}
		}
		return out
	}
	return nil
}

func anySocket(ev domain.Evidence, match func(map[string]any) bool) bool {
	sockets, _ := ev.NormalizedData["sockets"].([]any)
	for _, item := range sockets {
		sock, _ := item.(map[string]any)
		if sock != nil && match(sock) {
			return true
		}
	}
	return false
}

func anyNamed(ev domain.Evidence, field string, approved []string) bool {
	items, _ := ev.NormalizedData[field].([]any)
	for _, item := range items {
		switch typed := item.(type) {
		case string:
			if !contains(approved, typed) {
				return true
			}
		case map[string]any:
			name, _ := typed["name"].(string)
			if name == "" {
				name, _ = typed["command"].(string)
			}
			if name != "" && !contains(approved, name) {
				return true
			}
		}
	}
	return false
}

func fingerprints(ev domain.Evidence) []string {
	keys, _ := ev.NormalizedData["authorized_keys"].([]any)
	out := make([]string, 0, len(keys))
	for _, item := range keys {
		rec, _ := item.(map[string]any)
		if rec == nil {
			continue
		}
		fp, _ := rec["fingerprint_sha256"].(string)
		if fp != "" {
			out = append(out, fp)
		}
	}
	return out
}

func stringSlice(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	index := map[string]int{}
	for _, item := range a {
		index[item]++
	}
	for _, item := range b {
		index[item]--
		if index[item] < 0 {
			return false
		}
	}
	return true
}

func pathUnder(path string, dirs []string) bool {
	path = strings.TrimSpace(path)
	for _, dir := range dirs {
		dir = strings.TrimRight(dir, "/")
		if path == dir || strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}
