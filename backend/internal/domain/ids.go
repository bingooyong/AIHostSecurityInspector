package domain

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

const (
	MaxEntityIDLen = 128
	MaxHostIDLen   = 64
	MaxTextLen     = 8000
	MaxShortText   = 500
	MaxHashHex     = 64
)

var (
	entityIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)
	hostIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	sha256Pattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	versionPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

func ValidEntityID(id string) bool {
	return entityIDPattern.MatchString(id)
}

func ValidHostID(id string) bool {
	if !hostIDPattern.MatchString(id) {
		return false
	}
	_, err := netip.ParseAddr(id)
	return err != nil
}

func ValidSHA256(h string) bool {
	return sha256Pattern.MatchString(h)
}

func ValidVersion(v string) bool {
	return versionPattern.MatchString(v)
}

func validSafeText(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	if strings.TrimSpace(s) != s {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

func uniqueNonEmpty(values []string, valid func(string) bool) bool {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if !valid(v) {
			return false
		}
		if _, ok := seen[v]; ok {
			return false
		}
		seen[v] = struct{}{}
	}
	return true
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
