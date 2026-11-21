package ssh

import (
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const CollectorBinary = "hostsec-collector"

// BuildCollectorArgs returns the fixed argv for a remote collector invocation.
// Tokens are closed constants plus already-validated identifiers.
func BuildCollectorArgs(module, scanID, attemptID, hostID, profile, policyVersion string) ([]string, error) {
	if !domain.ValidEntityID(module) || !domain.ValidEntityID(scanID) || !domain.ValidEntityID(attemptID) || !domain.ValidHostID(hostID) {
		return nil, ErrArbitraryExec
	}
	if !domain.ValidProfile(profile) || !domain.ValidVersion(policyVersion) {
		return nil, ErrArbitraryExec
	}
	args := []string{
		"collect",
		"--module", module,
		"--scan-id", scanID,
		"--attempt-id", attemptID,
		"--host-id", hostID,
		"--profile", profile,
		"--policy-version", policyVersion,
		"--json",
	}
	for _, arg := range args {
		if arg == "" || strings.ContainsAny(arg, ";|&`$(){}[]<>\\\"'") || strings.ContainsRune(arg, 0) || strings.ContainsAny(arg, " \t\n") && !strings.HasPrefix(arg, "--") && arg != "collect" {
			// identifiers never contain spaces; flags are constants
			if strings.ContainsAny(arg, " \t\n") {
				return nil, ErrArbitraryExec
			}
		}
		if strings.ContainsAny(arg, ";|&`$(){}[]<>\\\"'") || strings.ContainsRune(arg, 0) {
			return nil, ErrArbitraryExec
		}
	}
	return args, nil
}

// JoinCommand concatenates an already-validated argv. The remote exec string is
// built only from those tokens; callers must not pass unsanitized input.
func JoinCommand(binary string, args []string) (string, error) {
	if binary != CollectorBinary {
		return "", ErrArbitraryExec
	}
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, binary)
	parts = append(parts, args...)
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, ";|&`$(){}[]<>\\\"' \t\n") || strings.ContainsRune(part, 0) {
			return "", ErrArbitraryExec
		}
	}
	return strings.Join(parts, " "), nil
}

// ParseCollectorCommand strictly tokenizes SSH_ORIGINAL_COMMAND or an exec string.
func ParseCollectorCommand(raw string) ([]string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return nil, ErrArbitraryExec
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 || fields[0] != CollectorBinary {
		return nil, ErrArbitraryExec
	}
	for _, field := range fields {
		if strings.ContainsAny(field, ";|&`$(){}[]<>\\\"'") {
			return nil, ErrArbitraryExec
		}
	}
	return fields, nil
}
