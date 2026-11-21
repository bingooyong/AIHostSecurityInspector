package intel

import (
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

type Report struct {
	Status  string   `json:"status"`
	Matches int      `json:"matches"`
	Notes   []string `json:"notes"`
}

func Correlate(evidence []domain.Evidence, catalog map[string][]string) Report {
	if catalog == nil {
		return Report{Status: domain.OutcomeUnknown, Matches: 0, Notes: []string{"offline vulnerability catalog is missing", "missing intel cannot be reported as no risk"}}
	}
	matches := 0
	for _, ev := range evidence {
		if ev.Module != "package_inventory" || !ev.SupportsDetection() {
			continue
		}
		records, _ := ev.NormalizedData["records"].([]any)
		for _, item := range records {
			rec, _ := item.(map[string]any)
			if rec == nil {
				continue
			}
			name, _ := rec["name"].(string)
			if len(catalog[name]) > 0 {
				matches++
			}
		}
	}
	return Report{Status: domain.OutcomeUnknown, Matches: matches, Notes: []string{"version comparison is advisory only; distro epoch/backport is not implemented"}}
}
