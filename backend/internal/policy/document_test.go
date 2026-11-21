package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinDocumentMatchesAssetAndRejectsUnsafePolicies(t *testing.T) {
	doc, err := BuiltinDocument()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(filepath.Join("..", "..", "..", "policies", "builtin-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PolicyID != doc.PolicyID || loaded.PolicyVersion != doc.PolicyVersion || len(loaded.Profiles) != 4 {
		t.Fatalf("builtin asset mismatch: %+v", loaded)
	}
	for _, name := range []string{"quick", "standard", "deep", "incident-response"} {
		want, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := loaded.Profile(name)
		if err != nil {
			t.Fatal(err)
		}
		wantHash, err := Hash(want)
		if err != nil {
			t.Fatal(err)
		}
		gotHash, err := Hash(got)
		if err != nil {
			t.Fatal(err)
		}
		if wantHash != gotHash {
			t.Fatalf("%s hash drifted: %s vs %s", name, wantHash, gotHash)
		}
	}

	for _, name := range []string{"invalid-module.json", "invalid-tool.json", "negative-limit.json", "enforced-true.json", "write-mode.json"} {
		if _, err := Load(filepath.Join("testdata", name)); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing policy accepted")
	}
	_ = os.RemoveAll(filepath.Join(t.TempDir(), "unused"))
}
