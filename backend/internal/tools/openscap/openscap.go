package openscap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

var (
	ErrContent = errors.New("openscap content pack does not match the target OS")
	ErrOffline = errors.New("openscap remediate and fetch are forbidden")
	ErrMissing = errors.New("openscap content pack is missing")
)

// OfficialContent maps precise OS IDs to content shipped by Debian's
// official scap-security-guide packages. There is no Debian 13 entry in
// ssg 0.1.76; a Debian 13 host must not be evaluated with Debian 12 content.
var OfficialContent = map[string]string{
	"debian-11":    "/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml",
	"debian-12":    "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
	"ubuntu-16.04": "/usr/share/xml/scap/ssg/content/ssg-ubuntu1604-ds.xml",
	"ubuntu-18.04": "/usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml",
	"ubuntu-20.04": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml",
	"ubuntu-22.04": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
	"ubuntu-24.04": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml",
}

type Request struct {
	OS         string
	ContentID  string
	ContentOS  string
	Profile    string
	Rule       string
	Chroot     string
	ResultsDir string
	Timeout    time.Duration
	LookPath   func(string) (string, error)
	Binary     string
	ExtraArgs  []string
}

func Run(ctx context.Context, req Request) (tools.Result, error) {
	for _, arg := range append([]string{}, req.ExtraArgs...) {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "remediate") || strings.Contains(lower, "fetch") {
			return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "forbidden_arg", Notes: []string{"offline eval only; remediate/fetch are forbidden"}}, ErrOffline
		}
	}
	if req.ContentID == "" {
		return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "missing_content"}, ErrMissing
	}
	if req.ContentOS == "" || req.OS == "" || req.ContentOS != req.OS {
		return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "content_os_mismatch", Notes: []string{"content pack must match the target OS"}}, ErrContent
	}
	if officialContentMismatch(req.OS, req.ContentID) {
		return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "content_os_mismatch", Notes: []string{"content filename belongs to a different OS or this OS has no official pack"}}, ErrContent
	}
	if _, err := os.Stat(req.ContentID); err != nil {
		// Fixture stubs may point at a label rather than a real datastream
		// when LookPath is replaced. Require a real file for the default
		// look path and for chroot evaluation.
		if req.LookPath == nil || req.Chroot != "" {
			return tools.Result{Tool: tools.ToolOpenSCAP, Status: domain.CollectionFailed, Warning: "missing_content", Notes: []string{"OS-matched content file was not found"}}, ErrMissing
		}
	}
	binary := req.Binary
	if binary == "" {
		if req.Chroot != "" {
			binary = "oscap-chroot"
		} else {
			binary = "oscap"
		}
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	args := []string{}
	if req.Chroot != "" {
		args = append(args, req.Chroot)
	}
	args = append(args, "xccdf", "eval")
	if req.Profile != "" {
		args = append(args, "--profile", req.Profile)
	}
	if req.Rule != "" {
		args = append(args, "--rule", req.Rule)
	}
	if req.ResultsDir != "" {
		abs, err := filepath.Abs(req.ResultsDir)
		if err != nil {
			return tools.Result{}, err
		}
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return tools.Result{}, err
		}
		args = append(args, "--results", filepath.Join(abs, "openscap-results.xml"))
	}
	args = append(args, req.ContentID)
	look := req.LookPath
	if look == nil {
		look = tools.LookPathWithFallbacks(nil, []string{"/usr/bin/oscap", "/usr/bin/oscap-chroot"})
	}
	// oscap-chroot has no --version flag; version comes from oscap itself when used live.
	versionArgs := []string{"--version"}
	if binary == "oscap-chroot" {
		versionArgs = nil
	}
	runner := tools.Runner{
		LookPath: look,
		Specs: map[string]tools.Spec{
			tools.ToolOpenSCAP: {Name: tools.ToolOpenSCAP, Binary: binary, Args: args, VersionArgs: versionArgs, Timeout: timeout, MaxOutput: 1 << 20},
		},
	}
	res, err := runner.Run(ctx, tools.Request{Tool: tools.ToolOpenSCAP})
	if res.Warning == "nonzero_exit" && strings.Contains(strings.Join(res.Notes, " | "), "exit_code: 2") {
		res.Warning = "rules_failed"
		res.Notes = append(res.Notes, "exit 2 means one or more XCCDF rules failed, not a missing scanner or a fetched remediate")
	}
	if res.Status == domain.CollectionSuccess || res.Warning == "rules_failed" {
		res.Notes = append(res.Notes, "offline eval only; remediate/fetch were not passed")
	}
	return res, err
}

func officialContentMismatch(osID, contentID string) bool {
	base := filepath.Base(contentID)
	if official, ok := OfficialContent[osID]; ok {
		if filepath.Base(official) == base || filepath.Clean(contentID) == filepath.Clean(official) {
			return false
		}
		// Fixture or locally copied content may use another filename for a
		// declared official OS; only reject when the basename is clearly a
		// different official OS datastream.
	}
	for otherOS, official := range OfficialContent {
		if otherOS == osID {
			continue
		}
		if filepath.Base(official) == base {
			return true
		}
	}
	return false
}
