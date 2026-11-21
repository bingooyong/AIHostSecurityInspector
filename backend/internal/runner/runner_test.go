package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/asset"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
)

func TestRunnerZoneSignatureReplay(t *testing.T) {
	inv, err := asset.Load(t.Context(), "../../../examples/hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../../examples/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := authorization.ParseDirectory(raw)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := dir.Lookup("operator-alice")
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "collector", "linux", "testdata", "host"))
	if err != nil {
		t.Fatal(err)
	}
	r := &Runner{
		Zone: "test-zone-a", Inventory: *inv, Caller: caller,
		Keys: map[string]ed25519.PublicKey{"runner-key": pub},
		Now:  func() time.Time { return time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC) },
	}
	task := Task{
		TaskID: "task-1", Zone: "test-zone-a", HostID: "linux-test-001", Profile: "quick",
		ScanID: "scan-runner-1", Root: root, OutDir: t.TempDir(), Expires: "2026-11-21T04:00:00Z",
		Nonce: "n1", KeyID: "runner-key",
	}
	signed, err := SignTask(priv, task)
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Execute(t.Context(), signed)
	if err != nil || result.ScanReady {
		t.Fatal(err, result)
	}
	if _, err := r.Execute(t.Context(), signed); err == nil {
		t.Fatal("replay accepted")
	}
	cross := signed
	cross.Zone = "test-zone-b"
	cross, err = SignTask(priv, Task{
		TaskID: "task-2", Zone: "test-zone-b", HostID: "linux-test-001", Profile: "quick",
		ScanID: "scan-runner-2", Root: root, OutDir: t.TempDir(), Expires: "2026-11-21T04:00:00Z",
		Nonce: "n2", KeyID: "runner-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute(t.Context(), cross); err == nil {
		t.Fatal("cross-zone task accepted")
	}
	bad := signed
	bad.Signature = "AAAA"
	if _, err := r.Execute(t.Context(), bad); err == nil {
		t.Fatal("bad signature accepted")
	}
}
