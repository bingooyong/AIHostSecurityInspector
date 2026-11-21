package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/app"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
)

type Server struct {
	Service   *app.Service
	Directory authorization.Directory
	limit     *limiter
}

func New(service *app.Service, directory authorization.Directory) *Server {
	return &Server{Service: service, Directory: directory, limit: newLimiter(30, time.Minute)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /v1/hosts", s.wrap(s.listHosts))
	mux.HandleFunc("GET /v1/profiles", s.wrap(s.listProfiles))
	mux.HandleFunc("POST /v1/plans", s.wrap(s.createPlan))
	mux.HandleFunc("POST /v1/approvals/requests", s.wrap(s.requestApproval))
	mux.HandleFunc("POST /v1/scans", s.wrap(s.createScan))
	mux.HandleFunc("GET /v1/scans", s.wrap(s.listScans))
	mux.HandleFunc("GET /v1/scans/{id}", s.wrap(s.getScan))
	mux.HandleFunc("GET /v1/scans/{id}/findings", s.wrap(s.listFindings))
	mux.HandleFunc("GET /v1/scans/{id}/evidence", s.wrap(s.listEvidence))
	mux.HandleFunc("GET /v1/evidence/{id}", s.wrap(s.getEvidence))
	mux.HandleFunc("GET /v1/approvals", s.wrap(s.listApprovals))
	mux.HandleFunc("GET /v1/audit", s.wrap(s.listAudit))
	mux.HandleFunc("POST /v1/scans/{id}/analyze", s.wrap(s.analyze))
	mux.HandleFunc("POST /v1/scans/{id}/report", s.wrap(s.report))
	return loopbackCORS(mux)
}

func ListenAllowed(addr string) error {
	if strings.HasPrefix(addr, "127.0.0.1:") {
		port := strings.TrimPrefix(addr, "127.0.0.1:")
		if port != "" && !strings.Contains(port, ":") {
			return nil
		}
	}
	if strings.HasPrefix(addr, "localhost:") {
		port := strings.TrimPrefix(addr, "localhost:")
		if port != "" && !strings.Contains(port, ":") {
			return nil
		}
	}
	return errors.New("API may bind loopback only")
}

func Serve(ctx context.Context, addr string, handler http.Handler) error {
	if err := ListenAllowed(addr); err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) wrap(next func(http.ResponseWriter, *http.Request, authorization.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if err := r.Context().Err(); err != nil {
			writeError(w, http.StatusRequestTimeout, app.CodeCancelled, "request cancelled")
			return
		}
		principalID := strings.TrimSpace(r.Header.Get("X-HostSec-Principal"))
		if principalID == "" {
			writeError(w, http.StatusUnauthorized, app.CodeAuthDenied, "caller identity header is required")
			return
		}
		caller, err := s.Directory.Lookup(principalID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, app.CodeAuthDenied, "caller is not a local trusted principal")
			return
		}
		if !s.limit.allow(caller.ID) {
			writeError(w, http.StatusTooManyRequests, app.CodeRateLimited, "principal rate limit exceeded")
			return
		}
		next(w, r, caller)
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"status":              "local",
		"collector_available": false,
		"scan_ready":          false,
		"execution_ready":     false,
	}, nil)
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	limit, offset, err := pageQuery(r)
	if err != nil {
		writeJSON(w, nil, err)
		return
	}
	hosts, err := s.Service.ListAuthorizedHosts(r.Context(), caller, limit, offset)
	writeJSON(w, hosts, err)
}

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	profiles, err := s.Service.ListScanProfiles(r.Context(), caller)
	writeJSON(w, profiles, err)
}

func (s *Server) createPlan(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	var in struct {
		HostID  string `json:"host_id"`
		Profile string `json:"profile"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeJSON(w, nil, err)
		return
	}
	rec, err := s.Service.PlanHostScan(r.Context(), caller, in.HostID, in.Profile)
	writeJSON(w, rec, err)
}

func (s *Server) requestApproval(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	var in struct {
		PlanID string `json:"plan_id"`
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeJSON(w, nil, err)
		return
	}
	rec, err := s.Service.RequestScanApproval(r.Context(), caller, in.PlanID, in.Reason)
	writeJSON(w, rec, err)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	var in struct {
		PlanID         string `json:"plan_id"`
		ApprovalID     string `json:"approval_id"`
		IdempotencyKey string `json:"idempotency_key"`
		HostID         string `json:"host_id"`
		Profile        string `json:"profile"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeJSON(w, nil, err)
		return
	}
	job, result, err := s.Service.RunHostScan(r.Context(), caller, in.PlanID, in.ApprovalID, in.IdempotencyKey, in.HostID, in.Profile)
	writeJSON(w, map[string]any{"job": job, "result": result}, err)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	limit, offset, err := pageQuery(r)
	if err != nil {
		writeJSON(w, nil, err)
		return
	}
	jobs, err := s.Service.ListScans(r.Context(), caller, limit, offset)
	writeJSON(w, jobs, err)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	job, err := s.Service.GetScanStatus(r.Context(), caller, r.PathValue("id"))
	writeJSON(w, job, err)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	limit, offset, err := pageQuery(r)
	if err != nil {
		writeJSON(w, nil, err)
		return
	}
	findings, rules, err := s.Service.ListFindings(r.Context(), caller, r.PathValue("id"), limit, offset)
	writeJSON(w, map[string]any{"findings": findings, "rule_results": rules}, err)
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	limit, offset, err := pageQuery(r)
	if err != nil {
		writeJSON(w, nil, err)
		return
	}
	items, err := s.Service.ListEvidence(r.Context(), caller, r.PathValue("id"), limit, offset)
	writeJSON(w, items, err)
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	limit, offset, err := pageQuery(r)
	if err != nil {
		writeJSON(w, nil, err)
		return
	}
	items, err := s.Service.ListApprovals(r.Context(), caller, limit, offset)
	writeJSON(w, items, err)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	limit, offset, err := pageQuery(r)
	if err != nil {
		writeJSON(w, nil, err)
		return
	}
	items, err := s.Service.ListAudit(r.Context(), caller, limit, offset)
	writeJSON(w, items, err)
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	meta, err := s.Service.GetEvidenceMetadata(r.Context(), caller, r.PathValue("id"))
	writeJSON(w, meta, err)
}

func (s *Server) analyze(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	result, err := s.Service.AnalyzeScanFindings(r.Context(), caller, r.PathValue("id"))
	writeJSON(w, result, err)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request, caller authorization.Principal) {
	var in struct {
		Format string `json:"format"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &in); err != nil {
			writeJSON(w, nil, err)
			return
		}
	}
	doc, markdown, err := s.Service.GenerateScanReport(r.Context(), caller, r.PathValue("id"), in.Format)
	writeJSON(w, map[string]any{"report": doc, "markdown": markdown}, err)
}

func pageQuery(r *http.Request) (int, int, error) {
	limit, offset := 0, 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, &app.Error{Code: app.CodeSchema, Message: "limit is invalid"}
		}
		limit = n
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, &app.Error{Code: app.CodeSchema, Message: "offset is invalid"}
		}
		offset = n
	}
	return limit, offset, nil
}

func loopbackCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); allowLoopbackOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-HostSec-Principal")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func allowLoopbackOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return host == "127.0.0.1" || host == "localhost"
}

func decodeBody(r *http.Request, dest any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("request too large")
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return err
	}
	for _, key := range []string{"role", "roles", "principal", "identity"} {
		if _, ok := probe[key]; ok {
			return failAuth("request JSON cannot self-assert identity or roles")
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dest)
}

func failAuth(message string) error {
	return &app.Error{Code: app.CodeAuthDenied, Message: message}
}

func writeJSON(w http.ResponseWriter, value any, err error) {
	if err != nil {
		status, code, message := statusFor(err)
		writeError(w, status, code, message)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func statusFor(err error) (int, string, string) {
	var coded *app.Error
	if errors.As(err, &coded) {
		switch coded.Code {
		case app.CodeAuthDenied:
			return http.StatusForbidden, coded.Code, coded.Message
		case app.CodeHostNotAuthorized:
			return http.StatusForbidden, coded.Code, coded.Message
		case app.CodeNotFound:
			return http.StatusNotFound, coded.Code, coded.Message
		case app.CodeApprovalRequired:
			return http.StatusConflict, coded.Code, coded.Message
		case app.CodeRateLimited:
			return http.StatusTooManyRequests, coded.Code, coded.Message
		case app.CodeCancelled:
			return http.StatusRequestTimeout, coded.Code, coded.Message
		default:
			return http.StatusBadRequest, coded.Code, coded.Message
		}
	}
	return http.StatusBadRequest, app.CodeSchema, "request failed"
}

type limiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{hits: map[string][]time.Time{}, max: max, window: window}
}

func (l *limiter) allow(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	kept := l.hits[id][:0]
	for _, ts := range l.hits[id] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= l.max {
		l.hits[id] = kept
		return false
	}
	l.hits[id] = append(kept, now)
	return true
}
