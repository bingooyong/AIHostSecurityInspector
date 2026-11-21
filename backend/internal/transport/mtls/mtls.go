package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

var (
	ErrNonLoopback = errors.New("mTLS endpoint must be loopback")
	ErrReplay      = errors.New("nonce already consumed")
	ErrExpired     = errors.New("nonce has expired")
	ErrVerify      = errors.New("mTLS certificate verification failed")
)

// LabBundle is a process-local CA plus leaf certificates.
// This is not a regional production trust bundle or platform IdP.
type LabBundle struct {
	CACert     *x509.Certificate
	CAKey      *ecdsa.PrivateKey
	ServerCert tls.Certificate
	ClientCert tls.Certificate
	Pool       *x509.CertPool
}

func NewLabBundle(now time.Time) (*LabBundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hostsec-lab-ca", Organization: []string{"HostSec lab"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	server, err := leaf(caCert, caKey, "hostsec-lab-server", now, true)
	if err != nil {
		return nil, err
	}
	client, err := leaf(caCert, caKey, "hostsec-lab-client", now, false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &LabBundle{CACert: caCert, CAKey: caKey, ServerCert: server, ClientCert: client, Pool: pool}, nil
}

func leaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, now time.Time, server bool) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (b *LabBundle) ServerTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{b.ServerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    b.Pool,
		MinVersion:   tls.VersionTLS13,
	}
}

func (b *LabBundle) ClientTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{b.ClientCert},
		RootCAs:      b.Pool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
	}
}

type NonceCache struct {
	mu   sync.Mutex
	used map[string]time.Time
	now  func() time.Time
}

func NewNonceCache(now func() time.Time) *NonceCache {
	if now == nil {
		now = time.Now
	}
	return &NonceCache{used: map[string]time.Time{}, now: now}
}

func (c *NonceCache) Consume(nonce string, expires time.Time) error {
	if nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	now := c.now()
	if !now.Before(expires) {
		return ErrExpired
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.used[nonce]; ok {
		return ErrReplay
	}
	c.used[nonce] = expires
	return nil
}

func ListenLoopback(addr string, cfg *tls.Config) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, ErrNonLoopback
	}
	return tls.Listen("tcp", addr, cfg)
}

func DialLoopback(addr string, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, ErrNonLoopback
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, ErrVerify
	}
	return conn, nil
}
