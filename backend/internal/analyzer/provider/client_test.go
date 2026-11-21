package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

func TestCompleteDisabledAndUnconfigured(t *testing.T) {
	res, err := (Client{}).Complete(context.Background(), []byte(`{"prompt":"x"}`))
	if err != nil || res.Status != domain.AIDisabled {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = (Client{Config: Config{Enabled: true}}).Complete(context.Background(), []byte(`{}`))
	if err != nil || res.Status != domain.AISkipped {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestCompleteTimeout4295xxAndOversize(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer slow.Close()
	host := mustHost(t, slow.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res, err := (Client{Config: Config{Enabled: true, Kind: KindLocal, BaseURL: slow.URL, AllowedHosts: []string{host}, Timeout: 20 * time.Millisecond}}).Complete(ctx, []byte(`{}`))
	if err == nil || res.Status != domain.AIFailed {
		t.Fatalf("timeout: %+v %v", res, err)
	}

	tooMany := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer tooMany.Close()
	res, err = (Client{Config: Config{Enabled: true, BaseURL: tooMany.URL, AllowedHosts: []string{mustHost(t, tooMany.URL)}}}).Complete(context.Background(), []byte(`{}`))
	if err == nil || res.Status != domain.AIFailed {
		t.Fatalf("429: %+v %v", res, err)
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer fail.Close()
	res, err = (Client{Config: Config{Enabled: true, BaseURL: fail.URL, AllowedHosts: []string{mustHost(t, fail.URL)}}}).Complete(context.Background(), []byte(`{}`))
	if err == nil || res.Status != domain.AIFailed {
		t.Fatalf("5xx: %+v %v", res, err)
	}

	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 100))
	}))
	defer big.Close()
	res, err = (Client{Config: Config{Enabled: true, BaseURL: big.URL, AllowedHosts: []string{mustHost(t, big.URL)}, MaxResponseBytes: 16}}).Complete(context.Background(), []byte(`{}`))
	if !errorsIsLimited(err) || res.Status != domain.AIFailed {
		t.Fatalf("oversize: %+v %v", res, err)
	}

	res, err = (Client{Config: Config{Enabled: true, BaseURL: big.URL, AllowedHosts: []string{mustHost(t, big.URL)}, MaxRequestBytes: 2}}).Complete(context.Background(), []byte(`{"k":"v"}`))
	if !errorsIsLimited(err) {
		t.Fatalf("request oversize: %v", err)
	}

	if _, err := (Client{Config: Config{Enabled: true, BaseURL: "https://evil.example", AllowedHosts: []string{"127.0.0.1"}}}).Complete(context.Background(), []byte(`{}`)); err != ErrSSRF {
		t.Fatalf("ssrf: %v", err)
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SECRET" {
			http.Error(w, "missing key", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ok.Close()
	res, err = (Client{Config: Config{Enabled: true, Kind: KindCompatible, BaseURL: ok.URL, APIKey: "SECRET", AllowedHosts: []string{mustHost(t, ok.URL)}}}).Complete(context.Background(), []byte(`{"prompt":"ok"}`))
	if err != nil || res.Status != domain.AISuccess {
		t.Fatalf("happy path: %+v %v", res, err)
	}
}

func errorsIsLimited(err error) bool {
	return err == ErrLimited
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}
