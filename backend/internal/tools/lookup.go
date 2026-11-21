package tools

import (
	"os"
	"os/exec"
	"path/filepath"
)

// LookPathWithFallbacks resolves an allowlisted binary from PATH first, then
// from well-known root-owned system locations such as /usr/sbin. It does not
// search user-writable directories beyond PATH.
func LookPathWithFallbacks(look func(string) (string, error), fallbacks []string) func(string) (string, error) {
	if look == nil {
		look = exec.LookPath
	}
	return func(name string) (string, error) {
		if name == "" {
			return "", os.ErrNotExist
		}
		if resolved, err := look(name); err == nil && resolved != "" {
			return resolved, nil
		}
		if filepath.IsAbs(name) {
			if info, err := os.Stat(name); err == nil && !info.IsDir() {
				return name, nil
			}
		}
		base := filepath.Base(name)
		for _, candidate := range fallbacks {
			if filepath.Base(candidate) != base && filepath.Base(candidate) != name {
				continue
			}
			info, err := os.Stat(candidate)
			if err != nil || info.IsDir() {
				continue
			}
			return candidate, nil
		}
		return "", os.ErrNotExist
	}
}
