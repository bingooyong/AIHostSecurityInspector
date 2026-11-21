package ssh

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// HostKeyPattern returns the literal OpenSSH known_hosts pattern for a
// loopback address and port. Port 22 may be written as a bare address.
func HostKeyPattern(address string, port int) (string, error) {
	ip, err := ParseLoopbackAddress(address)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("ssh port is invalid")
	}
	addr := ip.String()
	if port == 22 {
		return addr, nil
	}
	return fmt.Sprintf("[%s]:%d", addr, port), nil
}

// KnownHostsCovers reports whether a strict known_hosts file contains a
// literal entry for the loopback target. Hashed hostnames, wildcards, and
// certificate authorities are not accepted as a binding for this host.
func KnownHostsCovers(path, address string, port int) error {
	if err := ValidateKnownHosts(path); err != nil {
		return err
	}
	want, err := HostKeyPattern(address, port)
	if err != nil {
		return err
	}
	alt := ""
	if port == 22 {
		alt = fmt.Sprintf("[%s]:22", want)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrKnownHosts
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@") || strings.HasPrefix(line, "|") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		for _, pattern := range strings.Split(fields[0], ",") {
			if pattern == want || (alt != "" && pattern == alt) {
				return nil
			}
		}
	}
	if scanner.Err() != nil {
		return ErrKnownHosts
	}
	return ErrKnownHostsBinding
}
