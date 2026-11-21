package provider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const (
	KindOpenAI     = "openai"
	KindCompatible = "openai-compatible"
	KindLocal      = "local"
)

var (
	ErrDisabled      = errors.New("AI provider is disabled")
	ErrNotConfigured = errors.New("no approved model endpoint is configured")
	ErrLimited       = errors.New("provider request exceeded unified limits")
	ErrSSRF          = errors.New("provider URL is not on the allowlist")
	ErrStatus        = errors.New("provider returned a request error")
)

type Config struct {
	Enabled          bool
	Kind             string
	BaseURL          string
	APIKey           string
	Timeout          time.Duration
	MaxRequestBytes  int
	MaxResponseBytes int
	AllowedHosts     []string
}

type Result struct {
	Status string
	Body   []byte
	Notes  []string
}

type Client struct {
	Config Config
	HTTP   *http.Client
}

func (c Client) Complete(ctx context.Context, payload []byte) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !c.Config.Enabled {
		return Result{Status: domain.AIDisabled, Notes: []string{"AI is disabled by default", "no outbound request was sent"}}, nil
	}
	if c.Config.BaseURL == "" {
		return Result{Status: domain.AISkipped, Notes: []string{"no approved model endpoint is configured"}}, nil
	}
	maxReq := c.Config.MaxRequestBytes
	if maxReq <= 0 {
		maxReq = 32 << 10
	}
	maxResp := c.Config.MaxResponseBytes
	if maxResp <= 0 {
		maxResp = 32 << 10
	}
	if len(payload) > maxReq {
		return Result{Status: domain.AIFailed, Notes: []string{"request exceeded the byte limit"}}, ErrLimited
	}
	parsed, err := url.Parse(c.Config.BaseURL)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
		return Result{Status: domain.AIFailed, Notes: []string{"provider URL is invalid"}}, ErrSSRF
	}
	if !allowedHost(parsed.Hostname(), c.Config.AllowedHosts) {
		return Result{Status: domain.AIFailed, Notes: []string{"provider host is not allowlisted"}}, ErrSSRF
	}
	timeout := c.Config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrSSRF }}
	} else if client.CheckRedirect == nil {
		cp := *client
		cp.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrSSRF }
		client = &cp
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Config.BaseURL, bytes.NewReader(payload))
	if err != nil {
		return Result{Status: domain.AIFailed, Notes: []string{"provider request could not be built"}}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.Config.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{Status: domain.AIFailed, Notes: []string{"provider request timed out"}}, err
		}
		return Result{Status: domain.AIFailed, Notes: []string{"provider request failed"}}, err
	}
	defer func() { _ = resp.Body.Close() }()
	limited := io.LimitReader(resp.Body, int64(maxResp)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return Result{Status: domain.AIFailed, Notes: []string{"provider response could not be read"}}, err
	}
	if len(body) > maxResp {
		return Result{Status: domain.AIFailed, Notes: []string{"provider response exceeded the byte limit"}}, ErrLimited
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return Result{Status: domain.AIFailed, Notes: []string{"provider returned " + resp.Status}}, ErrStatus
	}
	if resp.StatusCode >= 400 {
		return Result{Status: domain.AIFailed, Notes: []string{"provider returned " + resp.Status}}, ErrStatus
	}
	return Result{Status: domain.AISuccess, Body: body, Notes: []string{"provider kind=" + normalizeKind(c.Config.Kind)}}, nil
}

func allowedHost(host string, allowed []string) bool {
	host = strings.ToLower(host)
	for _, item := range allowed {
		if strings.EqualFold(item, host) {
			return true
		}
	}
	return false
}

func normalizeKind(kind string) string {
	switch kind {
	case KindOpenAI, KindCompatible, KindLocal:
		return kind
	default:
		return KindCompatible
	}
}
