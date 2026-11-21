package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/evidence"
)

type Document struct {
	SchemaVersion string                      `json:"schema_version"`
	ScanID        string                      `json:"scan_id"`
	HostID        string                      `json:"host_id"`
	Profile       string                      `json:"profile"`
	Integrity     evidence.VerificationReport `json:"integrity"`
	Coverage      map[string]int              `json:"coverage"`
	RuleResults   []domain.RuleResult         `json:"rule_results"`
	Findings      []domain.Finding            `json:"findings"`
	Limitations   []string                    `json:"limitations"`
}

func Build(scanID, hostID, profile string, items []domain.Evidence, results []domain.RuleResult, findings []domain.Finding, integrity evidence.VerificationReport, limitations []string) Document {
	coverage := map[string]int{"evidence": len(items), "pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0, "findings": len(findings)}
	for _, result := range results {
		switch result.Outcome {
		case domain.OutcomePass:
			coverage["pass"]++
		case domain.OutcomeFail:
			coverage["fail"]++
		case domain.OutcomeUnknown:
			coverage["unknown"]++
		case domain.OutcomeNotApplicable:
			coverage["not_applicable"]++
		}
	}
	if limitations == nil {
		limitations = []string{}
	}
	return Document{
		SchemaVersion: "1.0", ScanID: scanID, HostID: hostID, Profile: profile,
		Integrity: integrity, Coverage: coverage, RuleResults: results, Findings: findings, Limitations: limitations,
	}
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
	tpl := template.Must(template.New("md").Parse(mdTemplate))
	file, err := os.OpenFile(mdPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if err := tpl.Execute(file, doc); err != nil {
		return "", err
	}
	return jsonPath, nil
}

const mdTemplate = `# HostSec fixture inspect report

- scan_id: {{.ScanID}}
- host_id: {{.HostID}}
- profile: {{.Profile}}
- integrity: {{.Integrity.Integrity}} (source authenticity {{.Integrity.SourceAuthenticity}})
- coverage: pass={{index .Coverage "pass"}} fail={{index .Coverage "fail"}} unknown={{index .Coverage "unknown"}} n/a={{index .Coverage "not_applicable"}} findings={{index .Coverage "findings"}}

## Limitations
{{range .Limitations}}- {{.}}
{{end}}
## Rule results
{{range .RuleResults}}- {{.RuleID}} {{.Outcome}} {{.ReasonCode}}
{{end}}
`

func Markdown(doc Document) string {
	var b strings.Builder
	_ = template.Must(template.New("md").Parse(mdTemplate)).Execute(&b, doc)
	return b.String()
}
