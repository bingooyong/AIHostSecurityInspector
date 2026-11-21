package bundle

import (
	"archive/tar"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func packSample(t *testing.T, dest, nonce string, priv ed25519.PrivateKey) SourceIdentity {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "report.json"), []byte(`{"scan_id":"scan-fixture-001"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := SourceIdentity{
		SourceID: "lab-box-1", HostID: "linux-test-001", ScanID: "scan-fixture-001",
		Region: "lab", CreatedAt: "2026-11-21T01:00:00Z", Nonce: nonce,
	}
	if err := Pack(src, dest, identity, "bundle-lab-1", priv); err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestImportAcceptsSignedBundleAndRejectsTamperReplayRegion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "bundle.tar.zst")
	logPath := filepath.Join(t.TempDir(), "import.jsonl")
	packSample(t, archive, "nonce-1", priv)
	dest := filepath.Join(t.TempDir(), "imported")
	opts := ImportOptions{Limits: DefaultLimits(), Public: pub, AllowedRegion: "lab", LogPath: logPath}
	identity, err := Import(archive, dest, opts)
	if err != nil {
		t.Fatal(err)
	}
	if identity.HostID != "linux-test-001" || identity.Nonce != "nonce-1" {
		t.Fatalf("%+v", identity)
	}
	if _, err := os.Stat(filepath.Join(dest, "report.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(archive, filepath.Join(t.TempDir(), "replay"), opts); err != ErrReplay {
		t.Fatalf("replay: %v", err)
	}

	// Missing identity: rewrite archive without the identity file.
	missing := filepath.Join(t.TempDir(), "missing.tar.zst")
	if err := rewriteArchive(archive, missing, func(name string, body []byte) (string, []byte, bool) {
		if name == IdentityName {
			return name, body, false
		}
		return name, body, true
	}); err != nil {
		t.Fatal(err)
	}
	missingDest := filepath.Join(t.TempDir(), "missing-dest")
	if _, err := Import(missing, missingDest, opts); err != ErrIdentity && err != ErrTamper {
		t.Fatalf("missing identity: %v", err)
	}
	if _, err := os.Stat(missingDest); !os.IsNotExist(err) {
		t.Fatal("failed import left a destination")
	}

	// Tampered identity inside a rewritten archive (signature no longer matches).
	tampered := filepath.Join(t.TempDir(), "tampered.tar.zst")
	if err := rewriteArchive(archive, tampered, func(name string, body []byte) (string, []byte, bool) {
		if name == IdentityName {
			var id SourceIdentity
			if err := json.Unmarshal(body, &id); err != nil {
				t.Fatal(err)
			}
			id.HostID = "linux-other-001"
			out, err := json.Marshal(id)
			if err != nil {
				t.Fatal(err)
			}
			return name, out, true
		}
		return name, body, true
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(tampered, filepath.Join(t.TempDir(), "tampered-dest"), opts); err != ErrTamper && err != ErrIdentity {
		t.Fatalf("tampered identity: %v", err)
	}

	// Cross-region
	opts.AllowedRegion = "prod-east"
	if _, err := Import(archive, filepath.Join(t.TempDir(), "region"), opts); err != ErrRegion && err != ErrReplay {
		// archive nonce already imported if we used same log; use a fresh log
		t.Fatalf("cross-region: %v", err)
	}
	fresh := ImportOptions{Limits: DefaultLimits(), Public: pub, AllowedRegion: "prod-east", LogPath: filepath.Join(t.TempDir(), "region.jsonl")}
	if _, err := Import(archive, filepath.Join(t.TempDir(), "region2"), fresh); err != ErrRegion {
		t.Fatalf("cross-region fresh log: %v", err)
	}
}

func TestUnpackRejectsPathSlip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Build a raw malicious archive with a ../ path.
	evil := filepath.Join(t.TempDir(), "evil.tar.zst")
	out, err := os.Create(evil)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(out)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	body := []byte("pwned")
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "dest")
	if err := unpackTo(evil, dest, DefaultLimits()); err != ErrPath {
		t.Fatalf("path slip: %v", err)
	}
	_ = priv
}

func rewriteArchive(src, dest string, keep func(name string, body []byte) (string, []byte, bool)) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	dec, err := zstd.NewReader(in)
	if err != nil {
		return err
	}
	defer dec.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	enc, err := zstd.NewWriter(out)
	if err != nil {
		return err
	}
	tr := tar.NewReader(dec)
	tw := tar.NewWriter(enc)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		body, err := ioReadAll(tr)
		if err != nil {
			return err
		}
		name, next, ok := keep(hdr.Name, body)
		if !ok {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(next)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(next); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return enc.Close()
}

func ioReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
