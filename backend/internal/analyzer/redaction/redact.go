package redaction

import (
	"errors"
	"regexp"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/analyzer"
)

const MaxFieldLen = 512

var ErrOutbound = errors.New("redaction failed closed; outbound request was not built")

var allowed = map[string]bool{
	"scan_id": true, "host_id": true, "finding_ids": true, "evidence_ids": true,
	"rule_ids": true, "titles": true, "categories": true,
}

var (
	pemRe    = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	keyRe    = regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token|authorization)\s*[:=]\s*\S+`)
	connRe   = regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^\s]+`)
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	sshKeyRe = regexp.MustCompile(`(?i)(ssh-(rsa|ed25519|dss)\s+\S+)`)
)

func RedactText(value string) string {
	out := pemRe.ReplaceAllString(value, "[REDACTED_PRIVATE_KEY]")
	out = connRe.ReplaceAllString(out, "[REDACTED_CONNECTION]")
	out = keyRe.ReplaceAllString(out, "${1}=[REDACTED]")
	out = sshKeyRe.ReplaceAllString(out, "[REDACTED_SSH_KEY]")
	out = emailRe.ReplaceAllString(out, "[REDACTED_EMAIL]")
	if len(out) > MaxFieldLen {
		out = out[:MaxFieldLen]
	}
	return out
}

func stillSecret(value string) bool {
	upper := strings.ToUpper(value)
	if strings.Contains(upper, "BEGIN ") && strings.Contains(upper, "PRIVATE KEY") && !strings.Contains(value, "[REDACTED_PRIVATE_KEY]") {
		return true
	}
	return connRe.MatchString(value) || pemRe.MatchString(value)
}

func Minimize(scanID, hostID string, findingIDs, evidenceIDs []string) (analyzer.View, error) {
	view := analyzer.View{
		ScanID: scanID, HostID: hostID,
		FindingIDs:  append([]string{}, findingIDs...),
		EvidenceIDs: append([]string{}, evidenceIDs...),
		Redactions:  []string{"argv", "environment", "private_key", "password", "connection_string", "email"},
	}
	for _, value := range append(append([]string{scanID, hostID}, view.FindingIDs...), view.EvidenceIDs...) {
		if stillSecret(value) {
			return analyzer.View{}, ErrOutbound
		}
	}
	return view, nil
}

func PrepareOutbound(fields map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for key, value := range fields {
		if !allowed[key] {
			continue
		}
		cleaned := RedactText(value)
		if stillSecret(cleaned) {
			return nil, ErrOutbound
		}
		out[key] = cleaned
	}
	return out, nil
}
