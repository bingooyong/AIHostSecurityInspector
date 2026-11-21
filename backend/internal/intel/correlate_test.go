package intel

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/vulnerability"
)

func TestMissingCatalogIsUnknownNotClean(t *testing.T) {
	report := Correlate(nil, nil)
	if report.Status != domain.OutcomeUnknown || report.Matches != 0 {
		t.Fatalf("%+v", report)
	}
}

func TestCorrelateCatalogUsesVersionedLibrary(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x44
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	cat, err := vulnerability.Load("../vulnerability/testdata/catalog-v1.json", pub, time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := domain.Evidence{
		Module: "package_inventory", CollectionStatus: domain.CollectionSuccess,
		IntegrityStatus: domain.IntegrityVerified, Completeness: domain.CompletenessComplete,
		SHA256: &hash, NormalizedSHA256: &hash,
		NormalizedData: map[string]any{
			"records": []any{map[string]any{"name": "openssl", "version": "3.3.1-1", "os": "debian"}},
		},
	}
	if !ev.SupportsDetection() {
		t.Fatal("test evidence must be usable")
	}
	report := CorrelateCatalog([]domain.Evidence{ev}, cat, pub, time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC))
	if report.Status != domain.OutcomeFail || report.Matches != 1 {
		t.Fatalf("expected FAIL from signed catalog: %+v", report)
	}
}
