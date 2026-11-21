package yara

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestYARAReviewedRulesScopeAndTimeout(t *testing.T) {
	bin, err := filepath.Abs(filepath.Join("testdata", "yara"))
	if err != nil {
		t.Fatal(err)
	}
	look := func(string) (string, error) { return bin, nil }
	reviewed, err := filepath.Abs(filepath.Join("testdata", "rules"))
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
	if _, err := Run(context.Background(), Request{RulePath: filepath.Join(reviewed, "evil-include.yar"), ReviewedDir: reviewed, Target: hit, ApprovedRoots: []string{root}, LookPath: look, Binary: "yara"}); err != ErrRule {
		t.Fatalf("include: %v", err)
	}
	if _, err := Run(context.Background(), Request{RulePath: filepath.Join(reviewed, "evil-extern.yar"), ReviewedDir: reviewed, Target: hit, ApprovedRoots: []string{root}, LookPath: look, Binary: "yara"}); err != ErrRule {
		t.Fatalf("external: %v", err)
	}
	if _, err := Run(context.Background(), Request{RulePath: filepath.Join(reviewed, "harmless.yar"), ReviewedDir: reviewed, Target: "/etc/passwd", ApprovedRoots: []string{root}, LookPath: look, Binary: "yara"}); err != ErrScope {
		t.Fatalf("scope: %v", err)
	}
	res, err := Run(context.Background(), Request{RulePath: filepath.Join(reviewed, "harmless.yar"), ReviewedDir: reviewed, Target: hit, ApprovedRoots: []string{root}, LookPath: look, Binary: "yara", PinnedVersion: "4.5.0", Timeout: 3 * time.Second})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("hit: %+v %v", res, err)
	}
	res, err = Run(context.Background(), Request{RulePath: filepath.Join(reviewed, "harmless.yar"), ReviewedDir: reviewed, Target: clean, ApprovedRoots: []string{root}, LookPath: look, Binary: "yara", PinnedVersion: "4.5.0", Timeout: 3 * time.Second})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("clean: %+v %v", res, err)
	}
}
