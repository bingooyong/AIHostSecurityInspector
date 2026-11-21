package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

type Report struct {
	OK      bool     `json:"ok"`
	Files   int      `json:"files"`
	Notes   []string `json:"notes"`
	Digests []string `json:"digests"`
}

func VerifyDir(root string) (Report, error) {
	report := Report{Notes: []string{"unsigned package remains untrusted", "hash is not host source authenticity"}, Digests: []string{}}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") {
			report.Notes = append(report.Notes, "path_rejected")
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			report.Notes = append(report.Notes, "symlink_rejected")
			report.OK = false
			return nil
		}
		if info.IsDir() {
			return nil
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(payload)
		report.Digests = append(report.Digests, hex.EncodeToString(sum[:]))
		report.Files++
		return nil
	})
	if err != nil {
		return report, err
	}
	report.OK = !contains(report.Notes, "symlink_rejected") && !contains(report.Notes, "path_rejected")
	return report, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
