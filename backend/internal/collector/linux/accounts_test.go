package linux

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func accountReq() collector.Request {
	return collector.Request{
		ScanID: "scan-fixture-001", AttemptID: "attempt-fixture-001", HostID: "linux-test-001",
		ModuleID: ModuleAccountInventory, Profile: domain.ProfileQuick, PolicyVersion: "0.1.0",
	}
}

func TestAccountInventoryFromFixture(t *testing.T) {
	col := Accounts{Root: fixtureRoot(t, "host"), Now: func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }}
	result, err := col.Collect(context.Background(), accountReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
	payload, _ := json.Marshal(result)
	text := string(payload)
	for _, leak := range []string{"SYNTHETIC_SHADOW_HASH_DO_NOT_LEAK", "SYNTHETIC_PRIVATE_KEY_DO_NOT_LEAK", "BEGIN OPENSSH PRIVATE KEY", "192.0.2.10", "198.51.100.9", "fixture-alice@example.test"} {
		if strings.Contains(text, leak) {
			t.Fatalf("sensitive value leaked: %s", leak)
		}
	}
	rec := result.Records[0]
	users := rec["users"].([]any)
	if len(users) != 4 {
		t.Fatalf("users=%v", users)
	}
	uid0 := rec["uid0"].([]any)
	if len(uid0) != 1 || uid0[0] != "root" {
		t.Fatalf("uid0=%v", uid0)
	}
	sudo := rec["sudo"].([]any)
	if len(sudo) < 2 {
		t.Fatalf("sudo=%v", sudo)
	}
	keys := rec["authorized_keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("keys=%v", keys)
	}
	for _, item := range keys {
		key := item.(map[string]any)
		fp, _ := key["fingerprint_sha256"].(string)
		if !domain.ValidSHA256(fp) || key["type"] != "ssh-ed25519" {
			t.Fatalf("key %+v", key)
		}
	}
	logins := rec["logins"].([]any)
	if len(logins) != 2 {
		t.Fatalf("logins=%v", logins)
	}
	skipped := rec["skipped_secrets"].([]any)
	joined := strings.Join(stringify(skipped), ",")
	if !strings.Contains(joined, "etc/shadow") || !strings.Contains(joined, "id_ed25519") {
		t.Fatalf("skipped=%v", skipped)
	}
}

func TestAccountSymlinkEscapeDoesNotReadShadow(t *testing.T) {
	col := Accounts{Root: fixtureRoot(t, "accounts-escape"), Now: time.Now}
	result, err := col.Collect(context.Background(), accountReq())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(result)
	if strings.Contains(string(payload), "SYNTHETIC_SHADOW_HASH_DO_NOT_LEAK") || strings.Contains(string(payload), "root:$") {
		t.Fatalf("escape leaked shadow: %s", payload)
	}
}

func TestAccountShadowIsNeverOpened(t *testing.T) {
	inner, err := openView(fixtureRoot(t, "host"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	view := &denySecretView{inner: inner}
	col := Accounts{Root: fixtureRoot(t, "host"), view: view, Now: time.Now}
	result, err := col.Collect(context.Background(), accountReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionSuccess && result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s", result.Status)
	}
	if view.openedShadow {
		t.Fatal("etc/shadow was opened")
	}
}

func TestAccountSudoPermissionDeniedIsPartial(t *testing.T) {
	inner, err := openView(fixtureRoot(t, "host"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	col := Accounts{Root: fixtureRoot(t, "host"), view: permPathView{inner: inner, deny: "etc/sudoers"}, Now: time.Now}
	result, err := col.Collect(context.Background(), accountReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionPartial {
		t.Fatalf("status=%s warnings=%v", result.Status, result.Warnings)
	}
}

func TestAccountLiveRootRejected(t *testing.T) {
	result, err := (Accounts{Root: "/", Now: time.Now}).Collect(context.Background(), accountReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionNotAvailable || result.ErrorCode != "ROOT_REJECTED" {
		t.Fatalf("live root accepted %+v", result)
	}
}

func TestAccountTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	col := Accounts{Root: fixtureRoot(t, "host"), view: hangView{ctx: ctx}, Now: time.Now}
	req := accountReq()
	req.Limits.Timeout = 20 * time.Millisecond
	result, err := col.Collect(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.CollectionTimeout {
		t.Fatalf("status=%s", result.Status)
	}
}

type denySecretView struct {
	inner        fileView
	openedShadow bool
}

func (d *denySecretView) ReadFile(name string) ([]byte, error) {
	if name == "etc/shadow" || name == "etc/gshadow" || strings.HasSuffix(name, "id_ed25519") {
		d.openedShadow = d.openedShadow || name == "etc/shadow"
		return nil, fs.ErrPermission
	}
	if strings.Contains(name, "PRIVATE KEY") {
		return nil, fs.ErrPermission
	}
	return d.inner.ReadFile(name)
}
func (d *denySecretView) Lstat(name string) (fs.FileInfo, error) { return d.inner.Lstat(name) }
func (d *denySecretView) Readlink(name string) (string, error)   { return d.inner.Readlink(name) }
func (d *denySecretView) ReadDir(name string) ([]fs.DirEntry, error) {
	return d.inner.ReadDir(name)
}
func (d *denySecretView) Close() error { return nil }

type permPathView struct {
	inner fileView
	deny  string
}

func (p permPathView) ReadFile(name string) ([]byte, error) {
	if name == p.deny {
		return nil, fs.ErrPermission
	}
	return p.inner.ReadFile(name)
}
func (p permPathView) Lstat(name string) (fs.FileInfo, error) {
	if name == p.deny {
		return nil, fs.ErrPermission
	}
	return p.inner.Lstat(name)
}
func (p permPathView) Readlink(name string) (string, error) {
	if name == p.deny {
		return "", os.ErrPermission
	}
	return p.inner.Readlink(name)
}
func (p permPathView) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == p.deny {
		return nil, fs.ErrPermission
	}
	return p.inner.ReadDir(name)
}
func (permPathView) Close() error { return nil }

func stringify(values []any) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.(string))
	}
	return out
}
