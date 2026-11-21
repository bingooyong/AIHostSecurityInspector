package bundle

import (
	"crypto/ed25519"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/sign"
)

type unsignedReport struct {
	Files   int      `json:"files"`
	Notes   []string `json:"notes"`
	Digests []string `json:"digests"`
}

func CanonicalReport(report Report) ([]byte, error) {
	return sign.Canonical(unsignedReport{Files: report.Files, Notes: report.Notes, Digests: report.Digests})
}

func Sign(report Report, private ed25519.PrivateKey) (string, error) {
	canonical, err := CanonicalReport(report)
	if err != nil {
		return "", err
	}
	return sign.Sign(private, canonical)
}

func Verify(report Report, public ed25519.PublicKey, signature string) error {
	canonical, err := CanonicalReport(report)
	if err != nil {
		return err
	}
	return sign.Verify(public, canonical, signature)
}
