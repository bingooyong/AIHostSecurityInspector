package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(map[string]string{"scan_id": "scan-1", "sha256": "abc"})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(priv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, canonical, sig); err != nil {
		t.Fatal(err)
	}
	canonical[len(canonical)-2] ^= 0xff
	if err := Verify(pub, canonical, sig); err == nil {
		t.Fatal("tampered payload verified")
	}
}
