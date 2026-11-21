package intel

import (
	"crypto/ed25519"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/vulnerability"
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
	packages := vulnerability.PackagesFromEvidence(evidence)
	matches := 0
	for _, pkg := range packages {
		if len(catalog[pkg.Name]) > 0 {
			matches++
		}
	}
	return Report{Status: domain.OutcomeUnknown, Matches: matches, Notes: []string{"string catalog matches are advisory only; use a signed versioned catalog for epoch and backport comparison"}}
}

func CorrelateCatalog(evidence []domain.Evidence, cat vulnerability.Catalog, public ed25519.PublicKey, now time.Time) Report {
	eval := vulnerability.Evaluate(vulnerability.PackagesFromEvidence(evidence), cat, public, now)
	return Report{Status: eval.Status, Matches: eval.Matches, Notes: eval.Notes}
}
