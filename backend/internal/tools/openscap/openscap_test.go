package openscap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestOpenSCAPRejectsMismatchedContentAndRemediate(t *testing.T) {
	if _, err := Run(context.Background(), Request{OS: "debian-13", ContentID: "pack", ContentOS: "debian-12"}); err != ErrContent {
		t.Fatalf("mismatch: %v", err)
	}
	if _, err := Run(context.Background(), Request{OS: "debian-12", ContentID: "pack", ContentOS: "debian-12", ExtraArgs: []string{"--fetch-remote-resources"}}); err != ErrOffline {
		t.Fatalf("fetch: %v", err)
	}
	if _, err := Run(context.Background(), Request{OS: "debian-12", ContentID: "pack", ContentOS: "debian-12", ExtraArgs: []string{"--remediate"}}); err != ErrOffline {
		t.Fatalf("remediate: %v", err)
	}
	bin, err := filepath.Abs(filepath.Join("testdata", "oscap"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), Request{
		OS: "debian-12", ContentID: "testdata/ssg-debian.xml", ContentOS: "debian-12", Timeout: 3 * time.Second,
		Binary: "oscap", LookPath: func(string) (string, error) { return bin, nil },
	})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = Run(context.Background(), Request{
		OS: "debian-12", ContentID: "pack", ContentOS: "debian-12", LookPath: func(string) (string, error) { return "", os.ErrNotExist },
	})
	if err != nil || res.Status != domain.CollectionNotAvailable {
		t.Fatalf("missing: %+v %v", res, err)
	}
}
