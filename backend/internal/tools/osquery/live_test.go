package osquery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/tools"
)

func TestLiveOsqueryFixedQueries(t *testing.T) {
	if !tools.LiveToolsEnabled() {
		t.Skip("set HOSTSEC_LIVE_TOOLS=1 to run official osqueryi adapter tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Run(ctx, Request{
		QueryID:          "osquery_info",
		PinnedVersion:    "5.24.1",
		AllowedPlatforms: []string{"linux"},
		Timeout:          10 * time.Second,
	})
	if err != nil || res.Status != domain.CollectionSuccess {
		t.Fatalf("live osquery_info: %+v %v", res, err)
	}
	joined := strings.Join(res.Notes, "\n")
	if !strings.Contains(joined, "query_id: osquery_info") || !strings.Contains(joined, "5.24.1") {
		t.Fatalf("expected pinned query/version notes, got %q", joined)
	}
	osv, err := Run(ctx, Request{QueryID: "os_version", AllowedPlatforms: []string{"linux", "debian"}, Timeout: 10 * time.Second})
	if err != nil || osv.Status != domain.CollectionSuccess {
		t.Fatalf("live os_version: %+v %v", osv, err)
	}
	if osv.Output != "" || res.Output != "" {
		t.Fatal("live tests must not retain raw osquery rows")
	}
}
