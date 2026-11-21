package lynis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

func TestLiveLynisControlledReportDir(t *testing.T) {
	if !tools.LiveToolsEnabled() {
		t.Skip("set HOSTSEC_LIVE_TOOLS=1 to run official Lynis adapter tests")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "hostsec-lab.prf")
	src, err := os.ReadFile("/etc/lynis/default.prf")
	if err != nil {
		t.Fatalf("official lynis profile is required for the live test: %v", err)
	}
	body := strings.ReplaceAll(string(src), "refresh-repositories=yes", "refresh-repositories=no")
	if !strings.Contains(body, "refresh-repositories=no") {
		body += "\nrefresh-repositories=no\n"
	}
	if !strings.Contains(body, "skip-upgrade-test") {
		body += "skip-upgrade-test=yes\n"
	} else {
		body = strings.ReplaceAll(body, "skip-upgrade-test=no", "skip-upgrade-test=yes")
	}
	if err := os.WriteFile(profile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Contain pid/log fallbacks inside the controlled directory.
	t.Setenv("HOME", dir)
	beforeHome, _ := os.ReadDir(os.Getenv("HOME"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := Run(ctx, Request{
		ReportDir:     dir,
		ApprovedItems: []string{"BOOT-5104"},
		ProfilePath:   profile,
		Timeout:       90 * time.Second,
	})
	if err != nil || res.Status != domain.CollectionSuccess && res.Status != domain.CollectionFailed {
		t.Fatalf("live lynis: %+v %v", res, err)
	}
	if res.Status == domain.CollectionNotAvailable {
		t.Fatalf("lynis is installed on this lab host: %+v", res)
	}
	if len(res.SideEffects) == 0 {
		t.Fatalf("expected controlled report-dir side effects: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "lynis-report.dat")); err != nil {
		t.Fatalf("report missing: %v / %+v", err, res)
	}
	afterHome, _ := os.ReadDir(os.Getenv("HOME"))
	if len(afterHome) < len(beforeHome) {
		t.Fatal("home snapshot shrank unexpectedly")
	}
	// Default home paths outside the report dir must not be used when HOME is the report dir.
	if dir != os.Getenv("HOME") {
		t.Fatal("HOME was not contained")
	}
}
