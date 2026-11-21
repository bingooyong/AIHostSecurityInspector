package bundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatal("symlink package accepted")
	}
}
