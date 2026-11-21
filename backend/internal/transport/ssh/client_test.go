package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestDialConfigRejectsNonLoopbackAndRoot(t *testing.T) {
	kh := writeTemp(t, "known_hosts", "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyNotRealDataxx\n")
	id := writeTemp(t, "id", "not-a-key\n")
	cfg := DialConfig{Address: "192.0.2.10", Policy: Policy{User: "hostsec-audit", Port: 2222, KnownHostsPath: kh, HostKeyPolicy: "strict", AllowedBinary: CollectorBinary, AllowedArgs: []string{"collect"}}, IdentityPath: id}
	if err := cfg.Validate(); !errors.Is(err, ErrNonLoopback) {
		t.Fatalf("non-loopback: %v", err)
	}
	cfg.Address = "127.0.0.1"
	cfg.Policy.User = "root"
	if err := cfg.Validate(); err == nil {
		t.Fatal("root accepted")
	}
	cfg.Policy.User = "hostsec-audit"
	cfg.Policy.AllowedBinary = "bash"
	if err := cfg.Validate(); !errors.Is(err, ErrArbitraryExec) {
		t.Fatalf("arbitrary exec: %v", err)
	}
}

func TestRunCollectsOverStrictSSHAndRejectsMismatch(t *testing.T) {
	handler := func(cmd string) ([]byte, uint32) {
		if _, err := ParseCollectorCommand(cmd); err != nil {
			return []byte("bad"), 1
		}
		return []byte(`{"module_id":"host_identity","status":"success"}`), 0
	}
	env := startServer(t, handler)
	args, err := BuildCollectorArgs("host_identity", "scan-lab-001", "attempt-lab-001", "linux-box-lab-001", "quick", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := env.config()
	cfg.Policy.AllowedArgs = args
	out, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"host_identity"`)) {
		t.Fatalf("output=%s", out)
	}

	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := cryptossh.NewSignerFromKey(wrongPriv)
	if err != nil {
		t.Fatal(err)
	}
	wrongLine := knownhosts.Line([]string{net.JoinHostPort("127.0.0.1", strconv.Itoa(env.port))}, wrongSigner.PublicKey())
	badKH := writeTemp(t, "known_hosts_bad", wrongLine+"\n")
	cfg.Policy.KnownHostsPath = badKH
	if _, err := Run(context.Background(), cfg); !errors.Is(err, ErrHostKey) {
		t.Fatalf("mismatch: %v", err)
	}
}

func TestRunCancelAndTimeout(t *testing.T) {
	started := make(chan struct{})
	handler := func(string) ([]byte, uint32) {
		close(started)
		time.Sleep(2 * time.Second)
		return []byte("late"), 0
	}
	env := startServer(t, handler)
	args, err := BuildCollectorArgs("host_identity", "scan-lab-001", "attempt-lab-001", "linux-box-lab-001", "quick", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := env.config()
	cfg.Policy.AllowedArgs = args
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	if _, err := Run(ctx, cfg); err == nil {
		t.Fatal("cancel accepted")
	}
	env2 := startServer(t, func(string) ([]byte, uint32) {
		time.Sleep(2 * time.Second)
		return []byte("late"), 0
	})
	cfg2 := env2.config()
	cfg2.Policy.AllowedArgs = args
	ctx2, cancel2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel2()
	if _, err := Run(ctx2, cfg2); err == nil {
		t.Fatal("timeout accepted")
	}
}

func TestHostKeyDriftIsRejected(t *testing.T) {
	args, err := BuildCollectorArgs("host_identity", "scan-lab-001", "attempt-lab-001", "linux-box-lab-001", "quick", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	env := startServer(t, func(string) ([]byte, uint32) { return []byte(`{}`), 0 })
	cfg := env.config()
	cfg.Policy.AllowedArgs = args
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	env.shutdown()
	drifted := startServerOnPort(t, env.userPriv, 0, func(string) ([]byte, uint32) { return []byte(`{}`), 0 })
	cfg.Policy.Port = drifted.port
	if _, err := Run(context.Background(), cfg); !errors.Is(err, ErrHostKey) {
		t.Fatalf("drift accepted: %v", err)
	}
}

func TestCommandParserRejectsMetacharacters(t *testing.T) {
	if _, err := ParseCollectorCommand("hostsec-collector collect --module host_identity;id"); err == nil {
		t.Fatal("metachar accepted")
	}
	if _, err := BuildCollectorArgs("host_identity;id", "scan-lab-001", "attempt-lab-001", "linux-box-lab-001", "quick", "0.1.0"); err == nil {
		t.Fatal("bad module accepted")
	}
}

type testServer struct {
	port       int
	userPriv   ed25519.PrivateKey
	identity   string
	knownHosts string
	ln         net.Listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func (s *testServer) config() DialConfig {
	return DialConfig{
		Address:      "127.0.0.1",
		IdentityPath: s.identity,
		Timeout:      5 * time.Second,
		Policy: Policy{
			User: "hostsec-audit", Port: s.port, KnownHostsPath: s.knownHosts,
			HostKeyPolicy: "strict", AllowedBinary: CollectorBinary,
		},
	}
}

func (s *testServer) shutdown() {
	s.cancel()
	_ = s.ln.Close()
	s.wg.Wait()
}

func startServer(t *testing.T, handler func(string) ([]byte, uint32)) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return startServerOnPort(t, priv, 0, handler)
}

func startServerOnPort(t *testing.T, userPriv ed25519.PrivateKey, _ int, handler func(string) ([]byte, uint32)) *testServer {
	t.Helper()
	userSigner, err := cryptossh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	identity := filepath.Join(dir, "id_ed25519")
	block, err := cryptossh.MarshalPrivateKey(userPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}, hostSigner.PublicKey())
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &testServer{port: port, userPriv: userPriv, identity: identity, knownHosts: kh, ln: ln, cancel: cancel}
	cfg := &cryptossh.ServerConfig{PublicKeyCallback: func(conn cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
		if conn.User() != "hostsec-audit" || !bytes.Equal(key.Marshal(), userSigner.PublicKey().Marshal()) {
			return nil, errors.New("denied")
		}
		return &cryptossh.Permissions{}, nil
	}}
	cfg.AddHostKey(hostSigner)
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if ctx.Err() != nil {
				_ = conn.Close()
				return
			}
			go serveSSH(conn, cfg, handler)
		}
	}()
	t.Cleanup(func() { srv.shutdown() })
	return srv
}

func serveSSH(conn net.Conn, cfg *cryptossh.ServerConfig, handler func(string) ([]byte, uint32)) {
	defer func() { _ = conn.Close() }()
	_, chans, reqs, err := cryptossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go cryptossh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(cryptossh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return
		}
		go handleSession(ch, requests, handler)
	}
}

func handleSession(ch cryptossh.Channel, requests <-chan *cryptossh.Request, handler func(string) ([]byte, uint32)) {
	defer func() { _ = ch.Close() }()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var payload struct {
			Command string
		}
		if err := cryptossh.Unmarshal(req.Payload, &payload); err != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return
		}
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		out, code := handler(payload.Command)
		_, _ = ch.Write(out)
		_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{code}))
		_ = ch.Close()
		return
	}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
