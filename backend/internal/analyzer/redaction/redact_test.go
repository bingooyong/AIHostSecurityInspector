package redaction

import (
	"strings"
	"testing"
)

func TestRedactsSecretsAndFailCloses(t *testing.T) {
	text := RedactText("password=hunter2 api_key=sk-test postgres://user:pass@localhost:5432/db contact admin@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI -----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----")
	for _, part := range []string{"hunter2", "sk-test", "user:pass", "admin@example.com", "AAAAC3NzaC1lZDI1NTE5AAAAI", "BEGIN RSA PRIVATE KEY"} {
		if strings.Contains(text, part) {
			t.Fatalf("secret leaked %q in %s", part, text)
		}
	}
	out, err := PrepareOutbound(map[string]string{"titles": "token=abcd1234", "argv": "this must be dropped", "password": "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out["argv"]; ok {
		t.Fatal("non-allowlisted field was sent")
	}
	if strings.Contains(out["titles"], "abcd1234") {
		t.Fatal("token was not redacted")
	}
	if _, err := Minimize("scan-1", "linux-test-001", []string{"finding-1"}, []string{"evidence-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Minimize("scan-1", "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----", nil, nil); err != ErrOutbound {
		t.Fatalf("fail-open on planted key: %v", err)
	}
}
