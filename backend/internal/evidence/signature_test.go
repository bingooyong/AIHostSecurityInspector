package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestManifestSignatureRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	man := Manifest{SchemaVersion: ManifestSchema, ScanID: "scan-1", HostIDs: []string{"linux-test-001"}, Producer: "test", SignatureNote: "n"}
	if err := man.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := man.VerifySignature(pub); err != nil {
		t.Fatal(err)
	}
	man.ScanID = "scan-2"
	if err := man.VerifySignature(pub); err == nil {
		t.Fatal("tampered manifest verified")
	}
}
