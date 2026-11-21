package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestBundleSignatureRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report := Report{Files: 1, Notes: []string{"unsigned package remains untrusted"}, Digests: []string{"abc"}}
	sig, err := Sign(report, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(report, pub, sig); err != nil {
		t.Fatal(err)
	}
	report.Digests = []string{"def"}
	if err := Verify(report, pub, sig); err == nil {
		t.Fatal("tampered bundle verified")
	}
}
