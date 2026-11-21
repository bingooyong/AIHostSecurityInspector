package bundle

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/sign"
	"github.com/klauspost/compress/zstd"
)

const (
	IdentityName = "source-identity.json"
	ManifestName = "manifest.json"
)

var (
	ErrIdentity    = errors.New("source identity is missing or invalid")
	ErrTamper      = errors.New("bundle failed integrity or source-identity verification")
	ErrReplay      = errors.New("bundle import replay rejected")
	ErrRegion      = errors.New("bundle source region is not allowed")
	ErrLimits      = errors.New("bundle exceeds unpack limits")
	ErrPath        = errors.New("bundle path is unsafe")
	ErrTransaction = errors.New("bundle import transaction failed")
)

type Limits struct {
	MaxFiles     int
	MaxFileSize  int64
	MaxTotalSize int64
}

func DefaultLimits() Limits {
	return Limits{MaxFiles: 256, MaxFileSize: 1 << 20, MaxTotalSize: 8 << 20}
}

type SourceIdentity struct {
	SchemaVersion string `json:"schema_version"`
	SourceID      string `json:"source_id"`
	HostID        string `json:"host_id"`
	ScanID        string `json:"scan_id"`
	Region        string `json:"region"`
	CreatedAt     string `json:"created_at"`
	TreeHash      string `json:"tree_hash"`
	Nonce         string `json:"nonce"`
}

type FileMeta struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	Identity      SourceIdentity `json:"identity"`
	Files         []FileMeta     `json:"files"`
	Algorithm     string         `json:"algorithm"`
	KeyID         string         `json:"key_id"`
	Signature     string         `json:"signature"`
}

type unsignedManifest struct {
	SchemaVersion string         `json:"schema_version"`
	Identity      SourceIdentity `json:"identity"`
	Files         []FileMeta     `json:"files"`
	Algorithm     string         `json:"algorithm"`
	KeyID         string         `json:"key_id"`
}

type ImportOptions struct {
	Limits        Limits
	Public        ed25519.PublicKey
	AllowedRegion string
	LogPath       string
}

func Pack(srcDir, destFile string, identity SourceIdentity, keyID string, private ed25519.PrivateKey) error {
	files, err := listRegularFiles(srcDir)
	if err != nil {
		return err
	}
	meta := make([]FileMeta, 0, len(files)+2)
	payloads := map[string][]byte{}
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(srcDir, rel))
		if err != nil {
			return err
		}
		payloads[rel] = body
		meta = append(meta, FileMeta{Path: rel, Size: int64(len(body)), SHA256: sha256Hex(body)})
	}
	identity.SchemaVersion = "1.0"
	identity.TreeHash = treeHash(meta)
	identityBody, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}
	identityBody = append(identityBody, '\n')
	payloads[IdentityName] = identityBody
	meta = append(meta, FileMeta{Path: IdentityName, Size: int64(len(identityBody)), SHA256: sha256Hex(identityBody)})
	man := Manifest{SchemaVersion: "1.0", Identity: identity, Files: meta, Algorithm: sign.AlgorithmEd25519, KeyID: keyID}
	canonical, err := sign.Canonical(unsignedManifest{SchemaVersion: man.SchemaVersion, Identity: man.Identity, Files: man.Files, Algorithm: man.Algorithm, KeyID: man.KeyID})
	if err != nil {
		return err
	}
	sig, err := sign.Sign(private, canonical)
	if err != nil {
		return err
	}
	man.Signature = sig
	manBody, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	manBody = append(manBody, '\n')
	payloads[ManifestName] = manBody

	if err := os.MkdirAll(filepath.Dir(destFile), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(destFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	enc, err := zstd.NewWriter(out)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(enc)
	// Deterministic order: identity, manifest, then other files already in walk order plus the two added.
	order := []string{IdentityName, ManifestName}
	for _, rel := range files {
		if rel != IdentityName && rel != ManifestName {
			order = append(order, rel)
		}
	}
	for _, rel := range order {
		body := payloads[rel]
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			_ = tw.Close()
			_ = enc.Close()
			return err
		}
		if _, err := tw.Write(body); err != nil {
			_ = tw.Close()
			_ = enc.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

func Import(archivePath, destDir string, opts ImportOptions) (SourceIdentity, error) {
	if opts.Limits.MaxFiles == 0 {
		opts.Limits = DefaultLimits()
	}
	if err := os.MkdirAll(filepath.Dir(destDir), 0o700); err != nil {
		return SourceIdentity{}, err
	}
	if _, err := os.Stat(destDir); err == nil {
		return SourceIdentity{}, errors.New("import destination already exists")
	}
	tmp, err := os.MkdirTemp(filepath.Dir(destDir), "hostsec-import-")
	if err != nil {
		return SourceIdentity{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := unpackTo(archivePath, tmp, opts.Limits); err != nil {
		return SourceIdentity{}, err
	}
	identity, err := verifyUnpacked(tmp, opts.Public)
	if err != nil {
		return SourceIdentity{}, err
	}
	if opts.AllowedRegion != "" && identity.Region != opts.AllowedRegion {
		return SourceIdentity{}, ErrRegion
	}
	if err := rejectReplay(opts.LogPath, identity); err != nil {
		return SourceIdentity{}, err
	}
	if err := os.Rename(tmp, destDir); err != nil {
		return SourceIdentity{}, ErrTransaction
	}
	// Prevent defer from removing the renamed dest: tmp no longer exists under that name
	// after rename, so RemoveAll is a no-op. Record the import after the rename succeeds.
	if err := recordImport(opts.LogPath, identity); err != nil {
		return SourceIdentity{}, err
	}
	return identity, nil
}

func unpackTo(archivePath, dest string, limits Limits) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dec, err := zstd.NewReader(f)
	if err != nil {
		return err
	}
	defer dec.Close()
	tr := tar.NewReader(dec)
	files := 0
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rel, err := safeRel(hdr.Name)
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeGNUSparse {
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			return ErrPath
		}
		if hdr.Size < 0 || hdr.Size > limits.MaxFileSize {
			return ErrLimits
		}
		files++
		if files > limits.MaxFiles {
			return ErrLimits
		}
		total += hdr.Size
		if total > limits.MaxTotalSize {
			return ErrLimits
		}
		target := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		written, copyErr := io.CopyN(out, tr, hdr.Size)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if written != hdr.Size {
			return ErrLimits
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func verifyUnpacked(dir string, public ed25519.PublicKey) (SourceIdentity, error) {
	identityBody, err := os.ReadFile(filepath.Join(dir, IdentityName))
	if err != nil {
		return SourceIdentity{}, ErrIdentity
	}
	var identity SourceIdentity
	if err := json.Unmarshal(identityBody, &identity); err != nil {
		return SourceIdentity{}, ErrIdentity
	}
	if identity.SchemaVersion != "1.0" || identity.SourceID == "" || !domain.ValidHostID(identity.HostID) || !domain.ValidEntityID(identity.ScanID) || identity.Nonce == "" || identity.Region == "" {
		return SourceIdentity{}, ErrIdentity
	}
	manBody, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return SourceIdentity{}, ErrTamper
	}
	var man Manifest
	if err := json.Unmarshal(manBody, &man); err != nil {
		return SourceIdentity{}, ErrTamper
	}
	if man.Signature == "" || man.Algorithm != sign.AlgorithmEd25519 {
		return SourceIdentity{}, ErrTamper
	}
	canonical, err := sign.Canonical(unsignedManifest{SchemaVersion: man.SchemaVersion, Identity: man.Identity, Files: man.Files, Algorithm: man.Algorithm, KeyID: man.KeyID})
	if err != nil {
		return SourceIdentity{}, err
	}
	if err := sign.Verify(public, canonical, man.Signature); err != nil {
		return SourceIdentity{}, ErrTamper
	}
	if man.Identity != identity {
		return SourceIdentity{}, ErrTamper
	}
	seen := map[string]FileMeta{}
	for _, file := range man.Files {
		seen[file.Path] = file
	}
	for _, file := range man.Files {
		body, err := os.ReadFile(filepath.Join(dir, file.Path))
		if err != nil {
			return SourceIdentity{}, ErrTamper
		}
		if int64(len(body)) != file.Size || sha256Hex(body) != file.SHA256 {
			return SourceIdentity{}, ErrTamper
		}
	}
	// The signed manifest lists every file except itself.
	disk, err := listRegularFiles(dir)
	if err != nil {
		return SourceIdentity{}, err
	}
	for _, rel := range disk {
		if rel == ManifestName {
			continue
		}
		if _, ok := seen[rel]; !ok {
			return SourceIdentity{}, ErrTamper
		}
	}
	if _, ok := seen[ManifestName]; ok {
		return SourceIdentity{}, ErrTamper
	}
	if len(disk) != len(man.Files)+1 {
		return SourceIdentity{}, ErrTamper
	}
	content := make([]FileMeta, 0, len(man.Files))
	for _, file := range man.Files {
		if file.Path != IdentityName && file.Path != ManifestName {
			content = append(content, file)
		}
	}
	if identity.TreeHash != treeHash(content) {
		return SourceIdentity{}, ErrTamper
	}
	return identity, nil
}

func safeRel(name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || strings.Contains(name, "\x00") {
		return "", ErrPath
	}
	cleaned := filepath.ToSlash(filepath.Clean(name))
	if cleaned == "." || strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") || strings.Contains(cleaned, "..") {
		return "", ErrPath
	}
	return cleaned, nil
}

func listRegularFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		if strings.Contains(rel, "..") {
			return ErrPath
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrPath
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return ErrPath
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	return files, err
}

func treeHash(files []FileMeta) string {
	type row struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	rows := make([]row, 0, len(files))
	for _, file := range files {
		if file.Path == IdentityName || file.Path == ManifestName {
			continue
		}
		rows = append(rows, row{Path: file.Path, SHA256: file.SHA256})
	}
	canonical, err := sign.Canonical(rows)
	if err != nil {
		return ""
	}
	return sha256Hex(canonical)
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type importRecord struct {
	SourceID string `json:"source_id"`
	ScanID   string `json:"scan_id"`
	Nonce    string `json:"nonce"`
	HostID   string `json:"host_id"`
	Region   string `json:"region"`
}

func rejectReplay(logPath string, identity SourceIdentity) error {
	if logPath == "" {
		return errors.New("import log is required")
	}
	payload, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(payload) > 0 && payload[len(payload)-1] != '\n' {
		return errors.New("import log is truncated")
	}
	start := 0
	for i, b := range payload {
		if b != '\n' {
			continue
		}
		line := payload[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var rec importRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return err
		}
		if rec.SourceID == identity.SourceID && rec.Nonce == identity.Nonce {
			return ErrReplay
		}
		if rec.ScanID == identity.ScanID && rec.SourceID == identity.SourceID {
			return ErrReplay
		}
	}
	return nil
}

func recordImport(logPath string, identity SourceIdentity) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(importRecord{
		SourceID: identity.SourceID, ScanID: identity.ScanID, Nonce: identity.Nonce, HostID: identity.HostID, Region: identity.Region,
	})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(append(body, '\n'))
	return err
}
