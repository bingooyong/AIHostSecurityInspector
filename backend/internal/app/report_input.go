package app

import (
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/orchestrator"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/policy"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/report"
)

func reportInputFromResult(result orchestrator.Result) report.Input {
	expected := make([]string, 0, len(result.Modules))
	for _, module := range result.Modules {
		expected = append(expected, module.ModuleID)
	}
	return report.Input{
		ScanID: result.ScanID, HostID: result.HostID, Profile: result.Profile, Status: result.JobStatus,
		CollectorVersion: collector.Version, PolicyVersion: policy.PolicyVersion, RuleBundleVersion: "0.1.0",
		Modules: result.Modules, ExpectedModules: expected, Evidence: result.Evidence,
		RuleResults: result.RuleResults, Findings: result.Findings, Integrity: result.Integrity,
		Limitations: result.Limitations, AIStatus: result.AIStatus,
	}
}
