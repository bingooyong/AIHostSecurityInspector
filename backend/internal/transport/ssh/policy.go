package ssh

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strings"
	"syscall"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

var (
	ErrInsecurePolicy    = errors.New("ssh host key policy is not strict")
	ErrKnownHosts        = errors.New("known_hosts is invalid")
	ErrKnownHostsBinding = errors.New("known_hosts does not bind the requested loopback target")
	ErrArbitraryExec     = errors.New("arbitrary remote command is rejected")
)

type Policy struct {
	User           string
	Port           int
	KnownHostsPath string
	HostKeyPolicy  string
	AllowedBinary  string
	AllowedArgs    []string
}

func Validate(p Policy) error {
	if p.User == "" || p.User == "root" {
		return &domain.Error{Code: domain.CodeInvalidCanonical, Message: "ssh user must be a dedicated non-root account"}
	}
	if p.Port < 1 || p.Port > 65535 {
		return &domain.Error{Code: domain.CodeInvalidCanonical, Message: "ssh port is invalid"}
	}
	if p.HostKeyPolicy != "strict" {
		return ErrInsecurePolicy
	}
	if p.AllowedBinary != "hostsec-collector" {
		return ErrArbitraryExec
	}
	for _, arg := range p.AllowedArgs {
		if arg == "" || strings.ContainsAny(arg, ";|&`$") {
			return ErrArbitraryExec
		}
	}
	return ValidateKnownHosts(p.KnownHostsPath)
}

func ValidateKnownHosts(path string) error {
	if path == "" {
		return ErrKnownHosts
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrKnownHosts
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrKnownHosts
	}
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@cert-authority") || strings.Contains(line, "*") {
			return ErrKnownHosts
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return ErrKnownHosts
		}
		lines++
	}
	if lines == 0 || scanner.Err() != nil {
		return ErrKnownHosts
	}
	return nil
}

func CommandLine(p Policy) ([]string, error) {
	if err := Validate(p); err != nil {
		return nil, err
	}
	out := []string{p.AllowedBinary}
	out = append(out, p.AllowedArgs...)
	return out, nil
}

func HasWildcard(raw []byte) bool {
	return bytes.Contains(raw, []byte("*"))
}
