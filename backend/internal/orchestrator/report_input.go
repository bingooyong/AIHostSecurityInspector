package orchestrator

import (
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/report"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/rules"
)

func reportInput(out Result, bundle rules.Bundle) report.Input {
	expected := make([]string, 0, len(out.Modules))
	for _, module := range out.Modules {
		expected = append(expected, module.ModuleID)
	}
	return report.Input{
		ScanID: out.ScanID, HostID: out.HostID, Profile: out.Profile, Status: out.JobStatus,
		CollectorVersion: collector.Version, PolicyVersion: policy.PolicyVersion, RuleBundleVersion: bundle.Version,
		Modules: out.Modules, ExpectedModules: expected, Evidence: out.Evidence,
		RuleResults: out.RuleResults, Findings: out.Findings, Integrity: out.Integrity,
		Limitations: out.Limitations, AIStatus: out.AIStatus,
	}
}
