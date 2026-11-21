package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	ErrIdentity = errors.New("ssh identity is invalid")
	ErrHostKey  = errors.New("ssh host key verification failed")
	ErrTimeout  = errors.New("ssh command timed out")
	ErrOutput   = errors.New("ssh command output exceeded the byte limit")
)

type DialConfig struct {
	Address        string
	Policy         Policy
	IdentityPath   string
	Timeout        time.Duration
	MaxOutputBytes int64
}

func (c DialConfig) Validate() error {
	if _, err := ParseLoopbackAddress(c.Address); err != nil {
		return err
	}
	if err := Validate(c.Policy); err != nil {
		return err
	}
	if c.IdentityPath == "" {
		return ErrIdentity
	}
	if c.MaxOutputBytes < 0 {
		return fmt.Errorf("ssh output limit is invalid")
	}
	return nil
}

func Run(ctx context.Context, cfg DialConfig) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	args, err := CommandLine(cfg.Policy)
	if err != nil {
		return nil, err
	}
	remote, err := JoinCommand(cfg.Policy.AllowedBinary, args[1:])
	if err != nil {
		return nil, err
	}
	signer, err := loadIdentity(cfg.IdentityPath)
	if err != nil {
		return nil, err
	}
	callback, err := strictHostKeyCallback(cfg.Policy.KnownHostsPath)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	maxOut := cfg.MaxOutputBytes
	if maxOut <= 0 {
		maxOut = 8 << 20
	}
	dialer := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Policy.Port))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	clientCfg := &cryptossh.ClientConfig{
		User:            cfg.Policy.User,
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)},
		HostKeyCallback: callback,
		Timeout:         timeout,
		HostKeyAlgorithms: []string{
			cryptossh.KeyAlgoED25519,
			cryptossh.KeyAlgoECDSA256,
			cryptossh.KeyAlgoRSASHA256,
		},
	}
	cc, chans, reqs, err := cryptossh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, ErrHostKey) {
			return nil, ErrHostKey
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			return nil, ErrHostKey
		}
		return nil, err
	}
	client := cryptossh.NewClient(cc, chans, reqs)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &limitedBuffer{buf: &stdout, max: maxOut}
	session.Stderr = &limitedBuffer{buf: &stderr, max: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- session.Run(remote) }()
	select {
	case <-ctx.Done():
		_ = session.Close()
		_ = client.Close()
		return nil, ctx.Err()
	case err := <-done:
		if errors.Is(err, errOutputLimit) {
			return nil, ErrOutput
		}
		if err != nil {
			return nil, err
		}
		return stdout.Bytes(), nil
	}
}

func loadIdentity(path string) (cryptossh.Signer, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrIdentity
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrIdentity
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<16))
	if err != nil {
		return nil, ErrIdentity
	}
	signer, err := cryptossh.ParsePrivateKey(data)
	for i := range data {
		data[i] = 0
	}
	if err != nil {
		return nil, ErrIdentity
	}
	return signer, nil
}

func strictHostKeyCallback(path string) (cryptossh.HostKeyCallback, error) {
	if err := ValidateKnownHosts(path); err != nil {
		return nil, err
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, ErrKnownHosts
	}
	return func(hostname string, remote net.Addr, key cryptossh.PublicKey) error {
		if err := cb(hostname, remote, key); err != nil {
			return ErrHostKey
		}
		return nil
	}, nil
}

var errOutputLimit = errors.New("output limit")

type limitedBuffer struct {
	buf *bytes.Buffer
	max int64
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if int64(l.buf.Len()+len(p)) > l.max {
		return 0, errOutputLimit
	}
	return l.buf.Write(p)
}
