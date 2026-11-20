package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func sample(t testing.TB) []byte {
	t.Helper()
	b, e := os.ReadFile("../../../examples/hosts.yaml")
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestParseYAMLAndJSON(t *testing.T) {
	inv, e := Parse(context.Background(), sample(t))
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(inv)
	if e != nil {
		t.Fatal(e)
	}
	round, e := Parse(context.Background(), b)
	if e != nil {
		t.Fatal(e)
	}
	if len(round.Hosts) != 2 || round.Hosts[0].ID != "linux-test-001" {
		t.Fatal("lost host identity")
	}
	out := inv.Authorized()
	if len(out.Hosts) != 1 || len(out.Groups["mixed"].Hosts) != 1 {
		t.Fatal("unauthorized host disclosed")
	}
}

func TestRejectMalformedAssets(t *testing.T) {
	base := string(sample(t))
	inv, e := Parse(context.Background(), []byte(base))
	if e != nil {
		t.Fatal(e)
	}
	jsonBytes, _ := json.Marshal(inv)
	tests := map[string]string{
		"unknown key":           strings.Replace(base, "version: 1", "version: 1\npassword: CANARY_SECRET", 1),
		"duplicate key":         strings.Replace(base, "authorized: true", "authorized: true\n    authorized: false", 1),
		"missing authorization": strings.Replace(base, "    authorized: true\n", "", 1),
		"duplicate host":        strings.Replace(base, "host_id: linux-denied-001", "host_id: linux-test-001", 1),
		"unsafe host id":        strings.Replace(base, "host_id: linux-test-001", "host_id: linux;echo", 1),
		"host key bypass":       strings.Replace(base, "host_key_policy: strict", "host_key_policy: insecure", 1),
		"root ssh":              strings.Replace(base, "user: hostsec-audit", "user: root", 1),
		"inline secret":         strings.Replace(base, "auth_ref: ssh-agent:pilot", "password: CANARY_SECRET", 1),
		"multi document":        base + "\n---\nversion: 1\n",
		"json duplicate":        strings.Replace(string(jsonBytes), `"version":1`, `"version":1,"version":2`, 1),
		"json case typo":        strings.Replace(string(jsonBytes), `"host_id"`, `"HOST_ID"`, 1),
		"json extra":            string(jsonBytes) + " {}",
		"json malformed":        "{version: 1}",
		"invalid IP":            strings.Replace(base, "192.0.2.10", "192.0.2.0/24", 1),
		"zone IP":               strings.Replace(base, "192.0.2.10", "fe80::1%eth0", 1),
		"bad group":             strings.Replace(base, "hosts: [linux-test-001]", "hosts: [not-registered]", 1),
		"duplicate member":      strings.Replace(base, "hosts: [linux-test-001]", "hosts: [linux-test-001, linux-test-001]", 1),
		"empty group":           strings.Replace(base, "hosts: [linux-test-001]", "hosts: []", 1),
		"bad profile":           strings.Replace(base, "quick, standard, deep", "quick, arbitrary, deep", 1),
		"duplicate profile":     strings.Replace(base, "quick, standard, deep", "quick, quick, deep", 1),
		"alias":                 strings.Replace(base, "addresses: [192.0.2.10]", "addresses: &addrs [192.0.2.10]", 1),
		"merge":                 "version: 1\nhosts: []\ngroups: {<<: {}}",
		"deep nesting":          "x: " + strings.Repeat("[", 50) + "0" + strings.Repeat("]", 50),
		"over size":             strings.Repeat("#", MaxBytes+1),
		"numeric string":        strings.Replace(base, "owner: team-demo", "owner: 12345", 1),
		"quoted auth":           strings.Replace(base, "authorized: true", `authorized: "true"`, 1),
		"missing labels":        strings.Replace(base, "    labels: []\n", "", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(context.Background(), []byte(input))
			if err == nil {
				t.Fatal("accepted malformed input")
			}
			if strings.Contains(err.Error(), "CANARY_SECRET") {
				t.Fatal("error leaked source")
			}
		})
	}
}

func TestEmptyAuthorizedViewRoundTrips(t *testing.T) {
	inv, err := Parse(context.Background(), sample(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range inv.Hosts {
		authorized := false
		inv.Hosts[i].Authorized = &authorized
	}
	view := inv.Authorized()
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(context.Background(), encoded); err != nil {
		t.Fatal("empty authorized view is not a valid inventory", err)
	}
}

func TestTooManyHosts(t *testing.T) {
	inv, err := Parse(context.Background(), sample(t))
	if err != nil {
		t.Fatal(err)
	}
	inv.Hosts = make([]Host, MaxHosts+1)
	if err := inv.Validate(); err == nil {
		t.Fatal("accepted too many hosts")
	}
}

func TestLoadBoundariesAndCancellation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "hosts.yaml")
	if err := os.WriteFile(file, sample(t), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), dir); err == nil {
		t.Fatal("accepted directory")
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(file, link); e != nil {
		t.Fatal(e)
	}
	if _, err := Load(context.Background(), link); err == nil {
		t.Fatal("accepted symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if _, err := Load(context.Background(), fifo); err == nil {
		t.Fatal("accepted fifo")
	}
	if _, err := Load(context.Background(), filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted missing file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, file); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func BenchmarkParse1000Hosts(b *testing.B) {
	inv, err := Parse(context.Background(), sample(b))
	if err != nil {
		b.Fatal(err)
	}
	first := inv.Hosts[0]
	inv.Hosts = nil
	inv.Groups = map[string]Group{}
	for i := range 1000 {
		h := first
		h.ID = fmt.Sprintf("host-%04d", i)
		inv.Hosts = append(inv.Hosts, h)
	}
	data, err := json.Marshal(inv)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := Parse(context.Background(), data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRejectNullConnectionScalars(t *testing.T) {
	inv, err := Parse(context.Background(), sample(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	hosts := document["hosts"].([]any)
	connection := hosts[1].(map[string]any)["connection"].(map[string]any)
	for _, field := range []string{"port", "user", "auth_ref", "known_hosts_ref"} {
		t.Run("json_"+field, func(t *testing.T) {
			connection[field] = nil
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(context.Background(), data); err == nil {
				t.Fatal("accepted explicit null scalar")
			}
			delete(connection, field)
		})
		t.Run("yaml_"+field, func(t *testing.T) {
			data := strings.Replace(string(sample(t)), "transport: local", "transport: local\n      "+field+": null", 1)
			if _, err := Parse(context.Background(), []byte(data)); err == nil {
				t.Fatal("accepted YAML null scalar")
			}
		})
	}
}

func TestHostIdentityCannotBeIPAddress(t *testing.T) {
	for _, id := range []string{"192.0.2.10", "127.0.0.1", "255.255.255.255", "::1", "2001:db8::1"} {
		if ValidHostID(id) {
			t.Fatal("accepted address as host identity", id)
		}
	}
	if !ValidID("192.0.2.10") {
		t.Fatal("group identifier alphabet unexpectedly changed")
	}
	for _, id := range []string{"host-192.0.2.10", "host-001", "999.1.2.3"} {
		if !ValidHostID(id) {
			t.Fatal("rejected non-address identifier", id)
		}
	}
	// Change group references too, proving rejection is at host identity validation,
	// rather than caused by a dangling relation in this fixture.
	yamlInput := strings.ReplaceAll(string(sample(t)), "linux-test-001", "192.0.2.10")
	if _, err := Parse(context.Background(), []byte(yamlInput)); err == nil {
		t.Fatal("accepted YAML IP-based host ID")
	}
	inv, err := Parse(context.Background(), sample(t))
	if err != nil {
		t.Fatal(err)
	}
	inv.Hosts[0].ID = "192.0.2.10"
	inv.Groups["pilot"] = Group{Hosts: []string{"192.0.2.10"}}
	inv.Groups["mixed"] = Group{Hosts: []string{"192.0.2.10", "linux-denied-001"}}
	if err := inv.Validate(); err == nil {
		t.Fatal("domain accepted IP-based host ID")
	}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(context.Background(), data); err == nil {
		t.Fatal("accepted JSON IP-based host ID")
	}
}
