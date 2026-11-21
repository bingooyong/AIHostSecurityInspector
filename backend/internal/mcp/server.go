package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/app"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/authorization"
)

const maxRequest = 1 << 20

var allowedTools = []string{
	"list_authorized_hosts",
	"list_scan_profiles",
	"plan_host_scan",
	"request_scan_approval",
	"run_host_scan",
	"get_scan_status",
	"list_findings",
	"get_evidence_metadata",
	"analyze_scan_findings",
	"generate_scan_report",
}

var forbiddenTools = []string{
	"execute_shell", "ssh_exec", "kill_process", "delete_file", "disable_service", "change_firewall",
}

type Server struct {
	Service *app.Service
	Caller  authorization.Principal
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (s Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, maxRequest)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := reader.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(bytes.TrimSpace(line)) == 0 {
				return nil
			}
		} else if err != nil {
			return err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			if errors.Is(err, io.EOF) {
				return nil
			}
			continue
		}
		if len(line) > maxRequest {
			if writeErr := writeRPC(out, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32600, Message: "request too large"}}); writeErr != nil {
				return writeErr
			}
			continue
		}
		resp := s.handle(ctx, line)
		if err := writeRPC(out, resp); err != nil {
			return err
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func (s Server) handle(ctx context.Context, line []byte) rpcResponse {
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.JSONRPC != "2.0" {
		return rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}}
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]string{"name": "hostsec-mcp", "version": "0.1.0-dev"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}
	case "notifications/initialized", "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		tools := make([]map[string]any, 0, len(allowedTools))
		for _, name := range allowedTools {
			tools = append(tools, map[string]any{"name": name, "description": "HostSec local stdio tool", "inputSchema": map[string]any{"type": "object"}})
		}
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		result, err := s.call(ctx, req.Params)
		if err != nil {
			code, message := appCode(err)
			resp.Error = &rpcError{Code: -32000, Message: message, Data: map[string]string{"code": code}}
			break
		}
		payload, _ := json.Marshal(result)
		resp.Result = map[string]any{"content": []map[string]string{{"type": "text", "text": string(payload)}}, "isError": false}
	default:
		resp.Error = &rpcError{Code: -32601, Message: "method not found"}
	}
	return resp
}

func (s Server) call(ctx context.Context, params json.RawMessage) (any, error) {
	var parsed struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := decodeStrict(params, &parsed); err != nil {
		return nil, fail(app.CodeSchema, "tool call schema is invalid")
	}
	if parsed.Name == "" {
		return nil, fail(app.CodeSchema, "tool name is required")
	}
	for _, name := range forbiddenTools {
		if parsed.Name == name {
			return nil, fail(app.CodeAuthDenied, "forbidden tool")
		}
	}
	if !allowed(parsed.Name) {
		return nil, fail(app.CodeSchema, "unknown tool")
	}
	args := parsed.Arguments
	if len(args) == 0 {
		args = []byte("{}")
	}
	if err := rejectSelfAssertedRole(args); err != nil {
		return nil, err
	}
	switch parsed.Name {
	case "list_authorized_hosts":
		return s.Service.ListAuthorizedHosts(ctx, s.Caller)
	case "list_scan_profiles":
		return s.Service.ListScanProfiles(ctx, s.Caller)
	case "plan_host_scan":
		var in struct {
			HostID  string `json:"host_id"`
			Profile string `json:"profile"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "plan arguments are invalid")
		}
		return s.Service.PlanHostScan(ctx, s.Caller, in.HostID, in.Profile)
	case "request_scan_approval":
		var in struct {
			PlanID string `json:"plan_id"`
			Reason string `json:"reason"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "approval request arguments are invalid")
		}
		return s.Service.RequestScanApproval(ctx, s.Caller, in.PlanID, in.Reason)
	case "run_host_scan":
		var in struct {
			PlanID         string `json:"plan_id"`
			ApprovalID     string `json:"approval_id"`
			IdempotencyKey string `json:"idempotency_key"`
			HostID         string `json:"host_id"`
			Profile        string `json:"profile"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "run arguments are invalid")
		}
		job, result, err := s.Service.RunHostScan(ctx, s.Caller, in.PlanID, in.ApprovalID, in.IdempotencyKey, in.HostID, in.Profile)
		if err != nil {
			return nil, err
		}
		return map[string]any{"job": job, "result": result}, nil
	case "get_scan_status":
		var in struct {
			ScanID string `json:"scan_id"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "status arguments are invalid")
		}
		return s.Service.GetScanStatus(ctx, s.Caller, in.ScanID)
	case "list_findings":
		var in struct {
			ScanID string `json:"scan_id"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "findings arguments are invalid")
		}
		findings, rules, err := s.Service.ListFindings(ctx, s.Caller, in.ScanID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"findings": findings, "rule_results": rules}, nil
	case "get_evidence_metadata":
		var in struct {
			EvidenceID string `json:"evidence_id"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "evidence arguments are invalid")
		}
		return s.Service.GetEvidenceMetadata(ctx, s.Caller, in.EvidenceID)
	case "analyze_scan_findings":
		var in struct {
			ScanID string `json:"scan_id"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "analyze arguments are invalid")
		}
		return s.Service.AnalyzeScanFindings(ctx, s.Caller, in.ScanID)
	case "generate_scan_report":
		var in struct {
			ScanID string `json:"scan_id"`
			Format string `json:"format"`
		}
		if err := decodeStrict(args, &in); err != nil {
			return nil, fail(app.CodeSchema, "report arguments are invalid")
		}
		doc, markdown, err := s.Service.GenerateScanReport(ctx, s.Caller, in.ScanID, in.Format)
		if err != nil {
			return nil, err
		}
		return map[string]any{"report": doc, "markdown": markdown}, nil
	default:
		return nil, fail(app.CodeSchema, "unknown tool")
	}
}

func rejectSelfAssertedRole(args json.RawMessage) error {
	var probe map[string]any
	if err := json.Unmarshal(args, &probe); err != nil {
		return fail(app.CodeSchema, "arguments are invalid")
	}
	for _, key := range []string{"role", "roles", "principal", "identity"} {
		if _, ok := probe[key]; ok {
			return fail(app.CodeAuthDenied, "request JSON cannot self-assert identity or roles")
		}
	}
	return nil
}

func allowed(name string) bool {
	for _, item := range allowedTools {
		if item == name {
			return true
		}
	}
	return false
}

func decodeStrict(raw json.RawMessage, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dest)
}

func writeRPC(out io.Writer, resp rpcResponse) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = out.Write(append(payload, '\n'))
	return err
}

func fail(code, message string) error {
	return &app.Error{Code: code, Message: message}
}

func appCode(err error) (string, string) {
	var coded *app.Error
	if errors.As(err, &coded) {
		return coded.Code, coded.Message
	}
	msg := err.Error()
	if strings.Contains(msg, "not authorized") {
		return app.CodeHostNotAuthorized, msg
	}
	return app.CodeSchema, "tool call failed"
}
