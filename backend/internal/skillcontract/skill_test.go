package skillcontract

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSkillAllowsOnlyImplementedCLIAndForbidsShell(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller missing")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	payload, err := os.ReadFile(filepath.Join(root, "integrations", "skills", "host-security-inspection", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, cmd := range []string{"hostsec version", "hostsec doctor", "hostsec assets", "hostsec plan", "hostsec intent", "hostsec preflight", "hostsec inspect-fixture"} {
		if !strings.Contains(text, cmd) {
			t.Fatalf("missing allowed command %s", cmd)
		}
	}
	for _, forbidden := range []string{"bash -c", "execute_shell", "ssh_exec", "hostsec scan", "mcp serve"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			// Forbidden items must be named as prohibitions.
			t.Fatalf("skill must explicitly forbid %s", forbidden)
		}
	}
	if !strings.Contains(text, "no shell") && !strings.Contains(text, "no arbitrary shell") && !strings.Contains(text, "has no shell") {
		t.Fatal("skill must deny arbitrary shell capability")
	}
	if !strings.Contains(text, "reject `/`") && !strings.Contains(text, "must reject `/`") {
		t.Fatal("skill must tell agents to reject live root")
	}
}
