package approval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

type storeFile struct {
	Principals []storePrincipal `json:"principals"`
	Revoked    []string         `json:"revoked_approval_ids"`
}

type storePrincipal struct {
	ID         string `json:"id"`
	KeyID      string `json:"key_id"`
	CanRequest bool   `json:"can_request"`
	CanApprove bool   `json:"can_approve"`
	PublicKey  string `json:"public_key"`
}

func LoadTrustStore(path string) (TrustStore, error) {
	data, err := readRegular(path, 1<<20)
	if err != nil {
		return TrustStore{}, err
	}
	var parsed storeFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return TrustStore{}, errors.New("trust store is invalid")
	}
	store := TrustStore{
		Principals:         map[string]Principal{},
		Keys:               map[string]ed25519.PublicKey{},
		RevokedApprovalIDs: map[string]bool{},
	}
	for _, item := range parsed.Principals {
		raw, err := hex.DecodeString(item.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return TrustStore{}, errors.New("trust store public key is invalid")
		}
		store.Principals[item.ID] = Principal{ID: item.ID, KeyID: item.KeyID, CanRequest: item.CanRequest, CanApprove: item.CanApprove}
		store.Keys[item.KeyID] = ed25519.PublicKey(raw)
	}
	for _, id := range parsed.Revoked {
		store.RevokedApprovalIDs[id] = true
	}
	return store, nil
}

func LoadDocument(path string) (*Document, error) {
	data, err := readRegular(path, 1<<20)
	if err != nil {
		return nil, err
	}
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("approval document is invalid")
	}
	return &doc, nil
}

func ReadBoundedFile(path string, max int64) ([]byte, error) {
	return readRegular(path, max)
}

func readRegular(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot open file")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > max {
		return nil, errors.New("file is not a bounded regular file")
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}
