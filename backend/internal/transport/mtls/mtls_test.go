package mtls

import (
	"io"
	"testing"
	"time"
)

func TestLabMTLSHandshakeAndReplay(t *testing.T) {
	bundle, err := NewLabBundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenLoopback("127.0.0.1:0", bundle.ServerTLS())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			done <- err
			return
		}
		_, err = conn.Write(buf[:n])
		done <- err
	}()
	conn, err := DialLoopback(ln.Addr().String(), bundle.ClientTLS(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := ListenLoopback("0.0.0.0:0", bundle.ServerTLS()); err != ErrNonLoopback {
		t.Fatalf("non-loopback listen: %v", err)
	}
	cache := NewNonceCache(time.Now)
	exp := time.Now().Add(time.Minute)
	if err := cache.Consume("nonce-1", exp); err != nil {
		t.Fatal(err)
	}
	if err := cache.Consume("nonce-1", exp); err != ErrReplay {
		t.Fatalf("replay: %v", err)
	}
	if err := cache.Consume("nonce-2", time.Now().Add(-time.Second)); err != ErrExpired {
		t.Fatalf("expired: %v", err)
	}
}
