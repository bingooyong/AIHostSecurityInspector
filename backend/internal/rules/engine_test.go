package rules

import (
	"context"
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/baseline"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestLoadRejectsUnknownPredicate(t *testing.T) {
	_, err := Load([]byte("bundle_id: x\nversion: 0.1.0\nplatform: linux\nrules:\n  - rule_id: PROC-001\n    version: \"1.0\"\n    title: t\n    category: process\n    platform: linux\n    profiles: [quick]\n    severity: high\n    confidence: 1\n    required_evidence: [process_inventory]\n    detection_logic: {predicate: eval}\n    false_positive_notes: n\n    remediation_guidance: [r]\n    references: [r]\n"))
	if err == nil {
		t.Fatal("eval predicate accepted")
	}
}

func TestNineRulesOutcomes(t *testing.T) {
	bundle, err := Load(DefaultBundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Rules) != 9 {
		t.Fatalf("rules=%d", len(bundle.Rules))
	}
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	process := usable("evidence-process-1", "process_inventory", "process", map[string]any{
		"records": []any{map[string]any{"pid": 99, "kernel_thread": false, "exe_reason": "deleted", "exe_path": "/tmp/demo-agent"}},
	}, hash)
	network := usable("evidence-network-1", "network_inventory", "network", map[string]any{
		"sockets": []any{map[string]any{"protocol": "tcp", "local_address": "0.0.0.0:23", "listening": true}},
	}, hash)
	account := usable("evidence-account-1", "account_inventory", "identity", map[string]any{
		"uid0":            []any{"root", "toor"},
		"authorized_keys": []any{map[string]any{"fingerprint_sha256": hash}},
	}, hash)
	service := usable("evidence-service-1", "service_inventory", "persistence", map[string]any{
		"units": []any{map[string]any{"name": "evil.service"}},
	}, hash)
	persist := usable("evidence-persist-1", "persistence_inventory", "persistence", map[string]any{
		"cron": []any{map[string]any{"command": "/tmp/job", "source": "etc/crontab"}},
	}, hash)
	files := usable("evidence-files-1", "targeted_file_scan", "malware", map[string]any{
		"records": []any{map[string]any{"path": "usr/local/bin/.hidden-tool", "suid": true}},
	}, hash)
	security := usable("evidence-security-1", "security_config", "config", map[string]any{
		"ssh": map[string]any{"permit_root_login": "yes", "password_authentication": "yes", "include_unresolved": true},
	}, hash)
	all := []domain.Evidence{process, network, account, service, persist, files, security}

	t.Run("missing evidence is UNKNOWN", func(t *testing.T) {
		results, findings, err := Evaluate(context.Background(), "scan-fixture-001", "linux-test-001", domain.ProfileQuick, nil, baseline.Candidate("linux-test-001", "scan-fixture-001"), bundle)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Fatal("missing evidence created findings")
		}
		for _, result := range results {
			if result.RuleID == "MAL-005" {
				if result.Outcome != domain.OutcomeNotApplicable {
					t.Fatalf("MAL-005 %s", result.Outcome)
				}
				continue
			}
			if result.Outcome != domain.OutcomeUnknown {
				t.Fatalf("%s=%s", result.RuleID, result.Outcome)
			}
		}
	})

	t.Run("fail with trusted baseline", func(t *testing.T) {
		base := baseline.Snapshot{
			HostID: "linux-test-001", ScanID: "scan-baseline-001", Status: baseline.StatusTrusted,
			UID0: []string{"root"}, Units: []string{"sshd.service"}, Cron: []string{"approved"},
			Fingerprints: []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			SUID:         []string{"usr/bin/passwd"}, ListenAllow: []string{"tcp/127.0.0.1:22"},
			ConfigHashes: map[string]string{"ssh": "no|no|false"}, SuspiciousDirs: []string{"/tmp"},
		}
		results, found, err := Evaluate(context.Background(), "scan-fixture-001", "linux-test-001", domain.ProfileStandard, all, base, bundle)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) == 0 {
			t.Fatal("expected findings")
		}
		byID := map[string]domain.RuleResult{}
		for _, result := range results {
			byID[result.RuleID] = result
		}
		for _, id := range []string{"PROC-001", "PROC-002", "NET-001", "IAM-001", "PERS-001", "PERS-002", "IAM-003", "MAL-005", "CFG-001"} {
			if byID[id].Outcome != domain.OutcomeFail {
				t.Fatalf("%s=%s %s", id, byID[id].Outcome, byID[id].ReasonCode)
			}
		}
	})

	t.Run("pass when condition not met", func(t *testing.T) {
		cleanProcess := usable("evidence-process-1", "process_inventory", "process", map[string]any{
			"records": []any{map[string]any{"pid": 1, "kernel_thread": false, "exe_reason": "exe_exists", "exe_path": "/usr/lib/systemd/systemd"}},
		}, hash)
		results, found, err := Evaluate(context.Background(), "scan-fixture-001", "linux-test-001", domain.ProfileQuick, []domain.Evidence{cleanProcess}, baseline.Candidate("linux-test-001", "scan-fixture-001"), bundle)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 0 {
			t.Fatalf("findings=%v", found)
		}
		if results[0].Outcome != domain.OutcomePass || results[0].RuleID != "PROC-001" {
			t.Fatalf("PROC-001 %+v", results[0])
		}
	})

	t.Run("unverified evidence cannot PASS or FAIL", func(t *testing.T) {
		bad := process
		bad.IntegrityStatus = domain.IntegrityUnverified
		results, found, err := Evaluate(context.Background(), "scan-fixture-001", "linux-test-001", domain.ProfileQuick, []domain.Evidence{bad}, baseline.Candidate("linux-test-001", "scan-fixture-001"), bundle)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 0 {
			t.Fatal("unverified evidence created findings")
		}
		if results[0].Outcome != domain.OutcomeUnknown {
			t.Fatalf("outcome=%s", results[0].Outcome)
		}
	})
}

func usable(id, module, category string, data map[string]any, hash string) domain.Evidence {
	sum := hash
	return domain.Evidence{
		EvidenceID: id, HostID: "linux-test-001", ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001",
		CollectedAt: "2026-11-21T00:00:00Z", ReceivedAt: "2026-11-21T00:00:01Z", Module: module,
		CollectorVersion: "0.1.0", Category: category, RawSummary: module + " fixture",
		NormalizedData: data, SHA256: &sum, NormalizedSHA256: &sum,
		CollectionStatus: domain.CollectionSuccess, IntegrityStatus: domain.IntegrityVerified,
		Completeness: domain.CompletenessComplete, Warnings: []string{},
	}
}
