package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/evidence"
)

// RequiredFields are the 17 user-facing scan-result items (schema_version is the envelope).
var RequiredFields = []string{
	"scan_id", "host_id", "profile", "status", "started_at", "completed_at",
	"collector_version", "policy_version", "rule_bundle_version",
	"collection_summary", "evidence", "rule_results", "findings",
	"ai_status", "ai_assessment", "limitations", "human_review",
}

type Input struct {
	ScanID            string
	HostID            string
	Profile           string
	Status            string
	StartedAt         string
	CompletedAt       string
	CollectorVersion  string
	PolicyVersion     string
	RuleBundleVersion string
	Modules           []collector.Result
	ExpectedModules   []string
	Evidence          []domain.Evidence
	RuleResults       []domain.RuleResult
	Findings          []domain.Finding
	Integrity         evidence.VerificationReport
	Limitations       []string
	AIStatus          string
	Assessment        *domain.Assessment
	HumanReview       domain.HumanReview
}

// Document is the JSON/Markdown scan report. Encoded fields match scan-result-v1.
type Document struct {
	SchemaVersion     string                      `json:"schema_version"`
	ScanID            string                      `json:"scan_id"`
	HostID            string                      `json:"host_id"`
	Profile           string                      `json:"profile"`
	Status            string                      `json:"status"`
	StartedAt         string                      `json:"started_at"`
	CompletedAt       string                      `json:"completed_at"`
	CollectorVersion  string                      `json:"collector_version"`
	PolicyVersion     string                      `json:"policy_version"`
	RuleBundleVersion string                      `json:"rule_bundle_version"`
	CollectionSummary domain.Coverage             `json:"collection_summary"`
	Evidence          []domain.Evidence           `json:"evidence"`
	RuleResults       []domain.RuleResult         `json:"rule_results"`
	Findings          []domain.Finding            `json:"findings"`
	AIStatus          string                      `json:"ai_status"`
	AIAssessment      *domain.Assessment          `json:"ai_assessment"`
	Limitations       []string                    `json:"limitations"`
	HumanReview       domain.HumanReview          `json:"human_review"`
	Uncovered         []string                    `json:"-"`
	Integrity         evidence.VerificationReport `json:"-"`
	RuleCoverage      map[string]int              `json:"-"`
}

func BuildFromInput(in Input) Document {
	if in.Evidence == nil {
		in.Evidence = []domain.Evidence{}
	}
	if in.RuleResults == nil {
		in.RuleResults = []domain.RuleResult{}
	}
	if in.Findings == nil {
		in.Findings = []domain.Finding{}
	}
	if in.Limitations == nil {
		in.Limitations = []string{}
	}
	if in.CollectorVersion == "" {
		in.CollectorVersion = collector.Version
	}
	if in.PolicyVersion == "" {
		in.PolicyVersion = "1.0"
	}
	if in.RuleBundleVersion == "" {
		in.RuleBundleVersion = "0.1.0"
	}
	if in.AIStatus == "" {
		in.AIStatus = domain.AIDisabled
	}
	if in.HumanReview.Status == "" {
		in.HumanReview.Status = "pending"
	}
	if in.HumanReview.Notes == nil {
		in.HumanReview.Notes = []string{}
	}
	if in.StartedAt == "" || in.CompletedAt == "" {
		now := time.Now().UTC().Format(domain.TimeLayout)
		if in.StartedAt == "" {
			in.StartedAt = firstModuleTime(in.Modules, now)
		}
		if in.CompletedAt == "" {
			in.CompletedAt = now
		}
	}

	summary, uncovered := summarizeCollection(in.Modules, in.ExpectedModules)
	limitations := append([]string{}, in.Limitations...)
	for _, module := range uncovered {
		limitations = append(limitations, "uncovered_module: "+module)
	}
	if summary.Coverage == nil || *summary.Coverage < 1 || hasUnknown(in.RuleResults) || in.Status != domain.JobCompleted {
		limitations = append(limitations, "incomplete collection or unknown rule results must not be interpreted as a secure host")
	}

	status := in.Status
	switch status {
	case domain.JobCompleted, domain.JobPartial, domain.JobFailed, domain.JobCancelled:
	default:
		status = domain.JobPartial
	}
	if (summary.Coverage == nil || *summary.Coverage < 1 || summary.Failed > 0 || summary.Skipped > 0 || hasUnknown(in.RuleResults)) && status == domain.JobCompleted {
		status = domain.JobPartial
	}
	if in.AIStatus != domain.AISuccess {
		in.Assessment = nil
	}

	ruleCoverage := map[string]int{"evidence": len(in.Evidence), "pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0, "findings": len(in.Findings), "rules": len(in.RuleResults)}
	for _, result := range in.RuleResults {
		switch result.Outcome {
		case domain.OutcomePass:
			ruleCoverage["pass"]++
		case domain.OutcomeFail:
			ruleCoverage["fail"]++
		case domain.OutcomeUnknown:
			ruleCoverage["unknown"]++
		case domain.OutcomeNotApplicable:
			ruleCoverage["not_applicable"]++
		}
	}

	return Document{
		SchemaVersion:     domain.SchemaV1,
		ScanID:            in.ScanID,
		HostID:            in.HostID,
		Profile:           in.Profile,
		Status:            status,
		StartedAt:         in.StartedAt,
		CompletedAt:       in.CompletedAt,
		CollectorVersion:  in.CollectorVersion,
		PolicyVersion:     in.PolicyVersion,
		RuleBundleVersion: in.RuleBundleVersion,
		CollectionSummary: summary,
		Evidence:          in.Evidence,
		RuleResults:       in.RuleResults,
		Findings:          in.Findings,
		AIStatus:          in.AIStatus,
		AIAssessment:      in.Assessment,
		Limitations:       limitations,
		HumanReview:       in.HumanReview,
		Uncovered:         uncovered,
		Integrity:         in.Integrity,
		RuleCoverage:      ruleCoverage,
	}
}

// Build is a compatibility wrapper used by older call sites.
func Build(scanID, hostID, profile string, items []domain.Evidence, results []domain.RuleResult, findings []domain.Finding, integrity evidence.VerificationReport, limitations []string) Document {
	return BuildFromInput(Input{
		ScanID: scanID, HostID: hostID, Profile: profile, Status: domain.JobPartial,
		Evidence: items, RuleResults: results, Findings: findings, Integrity: integrity, Limitations: limitations,
		AIStatus: domain.AIDisabled,
	})
}

func Write(dir string, doc Document) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	jsonPath := filepath.Join(dir, "report.json")
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(jsonPath, payload, 0o600); err != nil {
		return "", err
	}
	mdPath := filepath.Join(dir, "report.md")
	if err := os.WriteFile(mdPath, []byte(Markdown(doc)), 0o600); err != nil {
		return "", err
	}
	return jsonPath, nil
}

func Markdown(doc Document) string {
	var b strings.Builder
	funcs := template.FuncMap{"safe": safeMarkdown}
	tpl := template.Must(template.New("md").Funcs(funcs).Parse(mdTemplate))
	_ = tpl.Execute(&b, doc)
	return b.String()
}

func LooksSecure(doc Document, body string) bool {
	if doc.Status == domain.JobCompleted && (doc.CollectionSummary.Coverage != nil && *doc.CollectionSummary.Coverage == 1) && !hasUnknown(doc.RuleResults) {
		return false
	}
	lower := strings.ToLower(body)
	needles := []string{"全部安全", "all clear", "host is secure", "no risk", "fully secure", "all passed", "扫描全部通过"}
	for _, needle := range needles {
		if strings.Contains(lower, needle) || strings.Contains(body, needle) {
			return true
		}
	}
	return false
}

func summarizeCollection(modules []collector.Result, expected []string) (domain.Coverage, []string) {
	seen := map[string]collector.Result{}
	for _, module := range modules {
		seen[module.ModuleID] = module
	}
	names := append([]string{}, expected...)
	if len(names) == 0 {
		for _, module := range modules {
			names = append(names, module.ModuleID)
		}
	}
	summary := domain.Coverage{TotalModules: len(names)}
	uncovered := make([]string, 0)
	for _, name := range names {
		mod, ok := seen[name]
		if !ok {
			summary.Skipped++
			uncovered = append(uncovered, name)
			continue
		}
		switch mod.Status {
		case domain.CollectionSuccess:
			summary.Succeeded++
		case domain.CollectionFailed, domain.CollectionTimeout, domain.CollectionCancelled:
			summary.Failed++
			uncovered = append(uncovered, name)
		default:
			// partial / not_available / unknown
			if mod.Status == domain.CollectionNotAvailable {
				summary.Skipped++
			} else {
				summary.Failed++
			}
			uncovered = append(uncovered, name)
		}
	}
	if summary.TotalModules > 0 {
		value := float64(summary.Succeeded) / float64(summary.TotalModules)
		summary.Coverage = &value
	} else {
		zero := 0.0
		summary.Coverage = &zero
	}
	return summary, uncovered
}

func firstModuleTime(modules []collector.Result, fallback string) string {
	for _, module := range modules {
		if strings.TrimSpace(module.StartedAt) != "" {
			return module.StartedAt
		}
	}
	return fallback
}

func hasUnknown(results []domain.RuleResult) bool {
	for _, result := range results {
		if result.Outcome == domain.OutcomeUnknown {
			return true
		}
	}
	return false
}

func safeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "```", "'''")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, "|", "\\|")
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		trim := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "- ") || strings.HasPrefix(trim, "* ") {
			lines[i] = " " + line
		}
	}
	return strings.Join(lines, "\n")
}

const mdTemplate = `# HostSec inspection report

- scan_id: {{safe .ScanID}}
- host_id: {{safe .HostID}}
- profile: {{safe .Profile}}
- status: {{safe .Status}}
- started_at: {{safe .StartedAt}}
- completed_at: {{safe .CompletedAt}}
- collector_version: {{safe .CollectorVersion}}
- policy_version: {{safe .PolicyVersion}}
- rule_bundle_version: {{safe .RuleBundleVersion}}
- ai_status: {{safe .AIStatus}}
- human_review: {{safe .HumanReview.Status}}
- integrity: {{safe .Integrity.Integrity}} (source authenticity {{safe .Integrity.SourceAuthenticity}})
- coverage denominator: {{.CollectionSummary.TotalModules}} (succeeded={{.CollectionSummary.Succeeded}} failed={{.CollectionSummary.Failed}} skipped={{.CollectionSummary.Skipped}})
- rule coverage: pass={{index .RuleCoverage "pass"}} fail={{index .RuleCoverage "fail"}} unknown={{index .RuleCoverage "unknown"}} n/a={{index .RuleCoverage "not_applicable"}} findings={{index .RuleCoverage "findings"}}

## Limitations
{{range .Limitations}}- {{safe .}}
{{end}}
## Uncovered
{{if .Uncovered}}{{range .Uncovered}}- {{safe .}}
{{end}}{{else}}- none
{{end}}
## Human review
- status: {{safe .HumanReview.Status}}
{{range .HumanReview.Notes}}- {{safe .}}
{{end}}
## Evidence index
{{if .Evidence}}{{range .Evidence}}- {{safe .EvidenceID}} module={{safe .Module}} collection={{safe .CollectionStatus}} integrity={{safe .IntegrityStatus}}
{{end}}{{else}}- none
{{end}}
## Rule results
{{range .RuleResults}}- {{safe .RuleID}} {{safe .Outcome}} {{safe .ReasonCode}}
{{end}}
## Findings
{{if .Findings}}{{range .Findings}}- {{safe .FindingID}} {{safe .Title}} evidence={{range .EvidenceRefs}}{{safe .}} {{end}}
{{end}}{{else}}- none
{{end}}
`
