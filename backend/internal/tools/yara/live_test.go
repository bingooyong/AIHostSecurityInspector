package yara

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

func TestLiveYARAReviewedPackScopeAndTimeout(t *testing.T) {
	if !tools.LiveToolsEnabled() {
		t.Skip("set HOSTSEC_LIVE_TOOLS=1 to run official YARA adapter tests")
	}
	reviewed, err := filepath.Abs(filepath.Join("rules"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	hit := filepath.Join(root, "sample.txt")
	if err := os.WriteFile(hit, []byte("harmless_marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(root, "clean.txt")
	if err := os.WriteFile(clean, []byte("nothing"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Run(ctx, Request{
		RulePath: filepath.Join(reviewed, "hostsec_harmless.yar"), ReviewedDir: reviewed,
		Target: hit, ApprovedRoots: []string{root}, Timeout: 10 * time.Second,
	})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("hit: %+v %v", res, err)
	}
	res, err = Run(ctx, Request{
		RulePath: filepath.Join(reviewed, "hostsec_harmless.yar"), ReviewedDir: reviewed,
		Target: clean, ApprovedRoots: []string{root}, Timeout: 10 * time.Second,
	})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("clean: %+v %v", res, err)
	}
	if _, err := Run(ctx, Request{
		RulePath: filepath.Join(reviewed, "hostsec_harmless.yar"), ReviewedDir: reviewed,
		Target: "/etc/passwd", ApprovedRoots: []string{root}, Timeout: 5 * time.Second,
	}); err != ErrScope {
		t.Fatalf("scope: %v", err)
	}
}
