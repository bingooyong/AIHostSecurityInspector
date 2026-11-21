package clamav

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

func TestLiveClamAVScanApprovedEICAROnly(t *testing.T) {
	if !tools.LiveToolsEnabled() {
		t.Skip("set HOSTSEC_LIVE_TOOLS=1 to run official ClamAV adapter tests")
	}
	sigDir := "/var/lib/clamav"
	if _, err := os.Stat(filepath.Join(sigDir, "daily.cvd")); err != nil {
		if _, err2 := os.Stat(filepath.Join(sigDir, "main.cvd")); err2 != nil {
			t.Skip("official ClamAV signatures are not installed")
		}
	}
	root := t.TempDir()
	eicar := filepath.Join(root, "eicar.txt")
	payload := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	if err := os.WriteFile(eicar, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(root, "clean.txt")
	if err := os.WriteFile(clean, []byte("hostsec-clean-fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	hit, err := Run(ctx, Request{
		Path: eicar, ApprovedRoots: []string{root}, SignaturesDir: sigDir,
		Now: time.Now(), Timeout: 90 * time.Second, Binary: "clamscan",
	})
	if err != nil || hit.Warning != "threat_detected" || hit.Findings != 1 {
		t.Fatalf("eicar: %+v %v", hit, err)
	}
	if len(hit.SideEffects) != 0 {
		t.Fatalf("EICAR file was mutated: %+v", hit)
	}
	after, err := os.ReadFile(eicar)
	if err != nil || string(after) != string(payload) {
		t.Fatalf("EICAR content changed or was removed: %v %q", err, after)
	}
	ok, err := Run(ctx, Request{
		Path: clean, ApprovedRoots: []string{root}, SignaturesDir: sigDir,
		Now: time.Now(), Timeout: 90 * time.Second, Binary: "clamscan",
	})
	if err != nil || ok.Status != domain.CollectionSuccess || ok.Findings != 0 {
		t.Fatalf("clean: %+v %v", ok, err)
	}
	if _, err := Run(ctx, Request{
		Path: "/etc/passwd", ApprovedRoots: []string{root}, SignaturesDir: sigDir,
		Now: time.Now(), Timeout: 10 * time.Second, Binary: "clamscan",
	}); err != ErrPath {
		t.Fatalf("host path must stay rejected: %v", err)
	}
}
