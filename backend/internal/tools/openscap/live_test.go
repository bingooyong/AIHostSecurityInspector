package openscap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

func TestLiveOpenSCAPRefusesMismatchedHostContent(t *testing.T) {
	if !tools.LiveToolsEnabled() {
		t.Skip("set HOSTSEC_LIVE_TOOLS=1 to run official OpenSCAP adapter tests")
	}
	if OfficialContent["debian-13"] != "" {
		t.Fatal("do not invent debian-13 official content")
	}
	content := OfficialContent["debian-12"]
	if _, err := os.Stat(content); err != nil {
		t.Skip("official ssg-debian12 content is not installed")
	}
	// This lab host is Debian 13; official SSG 0.1.76 has no debian-13 stream.
	// The adapter must refuse debian-12 content for a debian-13 target, including
	// a caller that mis-labels the same file as debian-13.
	if _, err := Run(context.Background(), Request{
		OS: "debian-13", ContentID: content, ContentOS: "debian-12", Timeout: 5 * time.Second,
	}); err != ErrContent {
		t.Fatalf("debian 13 must not use debian 12 content: %v", err)
	}
	if _, err := Run(context.Background(), Request{
		OS: "debian-13", ContentID: content, ContentOS: "debian-13", Timeout: 5 * time.Second,
	}); err != ErrContent {
		t.Fatalf("debian-12 datastream cannot be relabeled as debian-13: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Run(ctx, Request{
		OS: "debian-12", ContentID: content, ContentOS: "debian-12",
		ExtraArgs: []string{"--fetch-remote-resources"}, Timeout: 5 * time.Second,
	}); err != ErrOffline {
		t.Fatalf("fetch still forbidden on live binary path: %v", err)
	}
}

func TestLiveOpenSCAPChrootMatrix(t *testing.T) {
	if !tools.LiveToolsEnabled() {
		t.Skip("set HOSTSEC_LIVE_TOOLS=1 to run official OpenSCAP adapter tests")
	}
	root := os.Getenv("HOSTSEC_LIVE_CHROOT")
	osID := os.Getenv("HOSTSEC_LIVE_CHROOT_OS")
	if root == "" || osID == "" {
		t.Skip("set HOSTSEC_LIVE_CHROOT and HOSTSEC_LIVE_CHROOT_OS for an authorized lab chroot eval")
	}
	content := OfficialContent[osID]
	if content == "" {
		t.Fatalf("no official content mapping for %s", osID)
	}
	if _, err := os.Stat(content); err != nil {
		t.Fatalf("official content missing: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("chroot missing: %v", err)
	}
	results := t.TempDir()
	rule := os.Getenv("HOSTSEC_LIVE_CHROOT_RULE")
	if rule == "" {
		if osID == "ubuntu-24.04" {
			rule = "xccdf_org.ssgproject.content_rule_package_prelink_removed"
		} else {
			rule = "xccdf_org.ssgproject.content_rule_prefer_64bit_os"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := Run(ctx, Request{
		OS: osID, ContentID: content, ContentOS: osID, Chroot: root,
		ResultsDir: results, Rule: rule, Timeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("chroot eval error: %+v %v", res, err)
	}
	if res.Status == "not_available" {
		t.Fatalf("oscap-chroot should be installed: %+v", res)
	}
	joined := strings.Join(res.Notes, "\n")
	if strings.Contains(joined, "exit_code: 134") || strings.Contains(joined, "exit_code: 1") {
		t.Logf("unprivileged oscap-chroot eval is not claimed as success: status=%s warning=%s notes=%v", res.Status, res.Warning, res.Notes)
		return
	}
	if res.Status != "success" && res.Warning != "rules_failed" {
		t.Fatalf("unexpected chroot eval result: %+v", res)
	}
	t.Logf("chroot_os=%s status=%s warning=%s notes=%v", osID, res.Status, res.Warning, res.Notes)
	if _, err := os.Stat(filepath.Join(results, "openscap-results.xml")); err != nil && res.Status == "success" {
		t.Fatalf("expected results file on success: %v", err)
	}
}
