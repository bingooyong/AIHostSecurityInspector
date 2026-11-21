package approval

import (
	"path/filepath"
	"testing"
)

func TestLedgerRejectsReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.json")
	ledger, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("abc"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("abc"); err != ErrReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Consume("abc"); err != ErrReplay {
		t.Fatal("replay survived process restart")
	}
}
