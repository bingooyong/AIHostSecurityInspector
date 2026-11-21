package clamav

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestClamAVEICARAndGuards(t *testing.T) {
	bin, err := filepath.Abs(filepath.Join("testdata", "clamdscan"))
	if err != nil {
		t.Fatal(err)
	}
	look := func(string) (string, error) { return bin, nil }
	root := t.TempDir()
	eicar := filepath.Join(root, "eicar.txt")
	if err := os.WriteFile(eicar, []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(root, "clean.txt")
	if err := os.WriteFile(clean, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if _, err := Run(context.Background(), Request{Path: eicar, ApprovedRoots: []string{root}, SignaturesUntil: now.Add(-time.Hour), Now: now, LookPath: look, Binary: "clamdscan"}); err != ErrSignatures {
		t.Fatalf("stale: %v", err)
	}
	if _, err := Run(context.Background(), Request{Path: "/etc/passwd", ApprovedRoots: []string{root}, SignaturesUntil: now.Add(time.Hour), Now: now, LookPath: look, Binary: "clamdscan"}); err != ErrPath {
		t.Fatalf("path: %v", err)
	}
	if _, err := Run(context.Background(), Request{Path: eicar, ApprovedRoots: []string{root}, SignaturesUntil: now.Add(time.Hour), Now: now, ExtraArgs: []string{"--remove"}, LookPath: look, Binary: "clamdscan"}); err != ErrMutation {
		t.Fatalf("mutation: %v", err)
	}
	hit, err := Run(context.Background(), Request{Path: eicar, ApprovedRoots: []string{root}, SignaturesUntil: now.Add(time.Hour), Now: now, LookPath: look, Binary: "clamdscan", Timeout: 3 * time.Second})
	if err != nil || hit.Warning != "threat_detected" || hit.Findings != 1 {
		t.Fatalf("eicar: %+v %v", hit, err)
	}
	ok, err := Run(context.Background(), Request{Path: clean, ApprovedRoots: []string{root}, SignaturesUntil: now.Add(time.Hour), Now: now, LookPath: look, Binary: "clamdscan", Timeout: 3 * time.Second})
	if err != nil || ok.Status != domain.CollectionSuccess || ok.Findings != 0 {
		t.Fatalf("clean: %+v %v", ok, err)
	}
}
