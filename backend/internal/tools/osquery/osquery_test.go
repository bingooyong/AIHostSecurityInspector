package osquery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func look(t *testing.T, dir string) func(string) (string, error) {
	t.Helper()
	bin, err := filepath.Abs(filepath.Join("testdata", dir, "osqueryi"))
	if err != nil {
		t.Fatal(err)
	}
	return func(string) (string, error) { return bin, nil }
}

func TestOsqueryFixedQueryAndGuards(t *testing.T) {
	ok := look(t, "ok")
	res, err := Run(context.Background(), Request{QueryID: "osquery_info", LookPath: ok, Binary: "osqueryi", PinnedVersion: "5.24.1", AllowedPlatforms: []string{"linux"}, Timeout: 3 * time.Second})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("info: %+v %v", res, err)
	}
	if res.Output != "" {
		t.Fatalf("raw output must not be retained: %+v", res)
	}

	if _, err := Run(context.Background(), Request{QueryID: "osquery_info", SQL: "SELECT * FROM processes;", LookPath: ok, Binary: "osqueryi"}); err != ErrCallerSQL {
		t.Fatalf("caller sql: %v", err)
	}
	if _, err := Run(context.Background(), Request{QueryID: ".tables", LookPath: ok, Binary: "osqueryi"}); err != ErrQuery && err != ErrCallerSQL {
		t.Fatalf("meta: %v", err)
	}
	if _, err := Run(context.Background(), Request{QueryID: "osquery_info", ExtraArgs: []string{"--extension", "evil.so"}, LookPath: ok, Binary: "osqueryi"}); err != ErrExtension {
		t.Fatalf("extension: %v", err)
	}
	if _, err := Run(context.Background(), Request{QueryID: "not-a-query", LookPath: ok, Binary: "osqueryi"}); err != ErrQuery {
		t.Fatalf("unknown: %v", err)
	}

	res, err = Run(context.Background(), Request{QueryID: "osquery_info", LookPath: look(t, "corrupt"), Binary: "osqueryi", Timeout: 3 * time.Second})
	if err != ErrOutput || res.Warning != "output_corrupt" {
		t.Fatalf("corrupt: %+v %v", res, err)
	}

	res, err = Run(context.Background(), Request{QueryID: "osquery_info", LookPath: look(t, "slow"), Binary: "osqueryi", Timeout: 200 * time.Millisecond})
	if err != nil || res.Status != domain.CollectionTimeout {
		t.Fatalf("timeout: %+v %v", res, err)
	}

	res, err = Run(context.Background(), Request{QueryID: "osquery_info", LookPath: look(t, "big"), Binary: "osqueryi", Timeout: 3 * time.Second, MaxOutput: 64})
	if err != nil || res.Status != domain.CollectionFailed || res.Warning != "output_limit" {
		t.Fatalf("limit: %+v %v", res, err)
	}

	res, err = Run(context.Background(), Request{QueryID: "osquery_info", LookPath: func(string) (string, error) { return "", os.ErrNotExist }, Binary: "osqueryi"})
	if err != nil || res.Status != domain.CollectionNotAvailable {
		t.Fatalf("missing: %+v %v", res, err)
	}
}
