package intel

import (
	"testing"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestMissingCatalogIsUnknownNotClean(t *testing.T) {
	report := Correlate(nil, nil)
	if report.Status != domain.OutcomeUnknown || report.Matches != 0 {
		t.Fatalf("%+v", report)
	}
}
