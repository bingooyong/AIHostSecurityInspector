package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const AlgorithmEd25519 = "ed25519"

var (
	ErrSignature = errors.New("signature is invalid")
	ErrKey       = errors.New("signing key is invalid")
)

func Canonical(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func Sign(private ed25519.PrivateKey, canonical []byte) (string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", ErrKey
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical)), nil
}

func Verify(public ed25519.PublicKey, canonical []byte, signature string) error {
	if len(public) != ed25519.PublicKeySize {
		return ErrKey
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return ErrSignature
	}
	if !ed25519.Verify(public, canonical, raw) {
		return ErrSignature
	}
	return nil
}
