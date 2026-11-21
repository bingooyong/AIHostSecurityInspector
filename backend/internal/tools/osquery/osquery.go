package osquery

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

var (
	ErrQuery     = errors.New("osquery query is not in the fixed catalog")
	ErrCallerSQL = errors.New("caller SQL and meta commands are forbidden")
	ErrExtension = errors.New("dynamic osquery extensions are forbidden")
	ErrPlatform  = errors.New("osquery platform is not in the allowlist")
	ErrVersion   = errors.New("osquery version is not the pinned version")
	ErrOutput    = errors.New("osquery output is not valid JSON")
)

// Query is a code-defined osquery request. SQL is never accepted from callers.
type Query struct {
	ID  string
	SQL string
}

// Catalog is the only allowed query set. Columns are pinned to avoid pulling
// host identity fields such as hostname or hardware UUID into default output.
var Catalog = map[string]Query{
	"osquery_info":  {ID: "osquery_info", SQL: "SELECT version, build_platform, build_distro FROM osquery_info;"},
	"os_version":    {ID: "os_version", SQL: "SELECT name, version, major, minor, patch, platform, platform_like, codename, arch FROM os_version;"},
	"platform_info": {ID: "platform_info", SQL: "SELECT vendor, version, extra FROM platform_info;"},
}

type Request struct {
	QueryID          string
	SQL              string
	ExtraArgs        []string
	Timeout          time.Duration
	LookPath         func(string) (string, error)
	Binary           string
	PinnedVersion    string
	AllowedPlatforms []string
	MaxOutput        int
}

func Run(ctx context.Context, req Request) (tools.Result, error) {
	if err := rejectCallerInput(req); err != nil {
		warning := "caller_sql"
		if errors.Is(err, ErrExtension) {
			warning = "extension_forbidden"
		}
		if errors.Is(err, ErrQuery) {
			warning = "unknown_query"
		}
		return tools.Result{Tool: tools.ToolOsquery, Status: domain.CollectionFailed, Warning: warning, Notes: []string{err.Error()}}, err
	}
	query, ok := Catalog[req.QueryID]
	if !ok {
		return tools.Result{Tool: tools.ToolOsquery, Status: domain.CollectionFailed, Warning: "unknown_query"}, ErrQuery
	}
	binary := req.Binary
	if binary == "" {
		binary = "osqueryi"
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	maxOut := req.MaxOutput
	if maxOut <= 0 {
		maxOut = 1 << 20
	}
	args := []string{"--disable_extensions", "--json", query.SQL}
	look := req.LookPath
	if look == nil {
		look = tools.LookPathWithFallbacks(nil, []string{"/usr/bin/osqueryi"})
	}
	runner := tools.Runner{
		LookPath: look,
		Specs: map[string]tools.Spec{
			tools.ToolOsquery: {Name: tools.ToolOsquery, Binary: binary, Args: args, VersionArgs: []string{"--version"}, Timeout: timeout, MaxOutput: maxOut},
		},
	}
	res, err := runner.Run(ctx, tools.Request{Tool: tools.ToolOsquery})
	if err != nil {
		return res, err
	}
	res.Notes = append([]string{"query_id: " + query.ID}, res.Notes...)
	if res.Status != domain.CollectionSuccess {
		return res, err
	}
	var rows []map[string]any
	if decodeErr := json.Unmarshal([]byte(strings.TrimSpace(res.Output)), &rows); decodeErr != nil {
		res.Status = domain.CollectionFailed
		res.Warning = "output_corrupt"
		res.Notes = append(res.Notes, "osquery JSON could not be parsed and is not a clean scan")
		res.Output = ""
		return res, ErrOutput
	}
	res.Output = ""
	res.Notes = append(res.Notes, "rows: "+itoa(len(rows)))
	if req.PinnedVersion != "" && !versionMatches(res.Notes, req.PinnedVersion) {
		res.Status = domain.CollectionFailed
		res.Warning = "version_mismatch"
		return res, ErrVersion
	}
	if len(req.AllowedPlatforms) > 0 && !platformAllowed(req.AllowedPlatforms, rows, res.Notes) {
		res.Status = domain.CollectionFailed
		res.Warning = "platform_mismatch"
		return res, ErrPlatform
	}
	_ = runtime.GOOS
	return res, nil
}

func rejectCallerInput(req Request) error {
	if strings.TrimSpace(req.SQL) != "" {
		return ErrCallerSQL
	}
	id := strings.TrimSpace(req.QueryID)
	if id == "" || strings.HasPrefix(id, ".") || strings.ContainsAny(id, "; \t") {
		return ErrQuery
	}
	lowerID := strings.ToLower(id)
	if strings.Contains(lowerID, "select") || strings.Contains(lowerID, "pragma") {
		return ErrCallerSQL
	}
	for _, arg := range req.ExtraArgs {
		lower := strings.ToLower(strings.TrimSpace(arg))
		if lower == "" {
			continue
		}
		if strings.HasPrefix(lower, ".") || strings.Contains(lower, "extension") || strings.Contains(lower, "connect") {
			return ErrExtension
		}
		if strings.Contains(lower, "select") || strings.Contains(lower, "pragma") {
			return ErrCallerSQL
		}
	}
	return nil
}

func versionMatches(notes []string, pinned string) bool {
	blob := strings.ToLower(strings.Join(notes, "\n"))
	return strings.Contains(blob, strings.ToLower(pinned))
}

func platformAllowed(allowed []string, rows []map[string]any, notes []string) bool {
	found := map[string]string{}
	for _, row := range rows {
		for _, key := range []string{"build_platform", "platform", "platform_like", "arch"} {
			if v, ok := row[key]; ok {
				if s, ok := v.(string); ok && s != "" {
					found[key] = strings.ToLower(s)
				}
			}
		}
	}
	blob := strings.ToLower(strings.Join(notes, "\n") + " " + runtime.GOOS)
	for _, allow := range allowed {
		allow = strings.ToLower(strings.TrimSpace(allow))
		if allow == "" {
			continue
		}
		if found["build_platform"] == allow || found["platform"] == allow || found["platform_like"] == allow || found["arch"] == allow {
			return true
		}
		if allow == runtime.GOOS || strings.Contains(blob, allow) {
			return true
		}
	}
	return false
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
