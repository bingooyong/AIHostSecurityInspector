package linux

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/collector"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/domain"
)

const ModuleNetworkInventory = "network_inventory"

type Network struct {
	Root string
	Now  func() time.Time
	view fileView
}

type networkRecord struct {
	Sockets          []socketRecord `json:"sockets"`
	Routes           []routeRecord  `json:"routes"`
	DNSNameservers   []string       `json:"dns_nameservers"`
	Firewall         firewallRecord `json:"firewall"`
	UnresolvedInodes []int64        `json:"unresolved_inodes"`
}

type socketRecord struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	RemoteAddress string `json:"remote_address"`
	State         string `json:"state"`
	Inode         int64  `json:"inode"`
	PID           int    `json:"pid"`
	PIDResolved   bool   `json:"pid_resolved"`
	Listening     bool   `json:"listening"`
}

type routeRecord struct {
	Interface   string `json:"interface"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Mask        string `json:"mask"`
}

type firewallRecord struct {
	Status string   `json:"status"`
	Tables []string `json:"tables"`
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func (n Network) Collect(ctx context.Context, req collector.Request) (collector.Result, error) {
	system := System(n)
	started := system.now().UTC()
	result := collector.Result{
		ModuleID:     ModuleNetworkInventory,
		Version:      collector.Version,
		StartedAt:    started.Format(domain.TimeLayout),
		Records:      []map[string]any{},
		RawRefs:      []string{},
		Warnings:     []string{},
		Status:       domain.CollectionFailed,
		Completeness: domain.CompletenessUnavailable,
	}
	if err := ctx.Err(); err != nil {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), err
	}
	if err := req.Validate(); err != nil {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), err
	}
	if req.ModuleID != ModuleNetworkInventory {
		return system.finish(result, started, domain.CollectionFailed, "INVALID_REQUEST"), &domain.Error{Code: domain.CodeInvalidID, Message: "network collector only implements network_inventory"}
	}
	if req.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Limits.Timeout)
		defer cancel()
	}
	if err := validateRoot(n.Root); err != nil {
		result.Warnings = append(result.Warnings, "collector_root_rejected")
		return system.finish(result, started, domain.CollectionNotAvailable, "ROOT_REJECTED"), nil
	}
	view := n.view
	if view == nil {
		opened, err := openView(n.Root, req.Limits.MaxBytes)
		if err != nil {
			result.Warnings = append(result.Warnings, "root_open_failed")
			return system.finish(result, started, domain.CollectionFailed, "ROOT_OPEN_FAILED"), nil
		}
		defer func() { _ = opened.Close() }()
		view = opened
	}
	record, refs, warnings, err := readNetwork(ctx, view)
	result.RawRefs = refs
	result.Warnings = append(result.Warnings, warnings...)
	if isContext(err) {
		return system.finish(result, started, statusForContext(err), "MODULE_"+strings.ToUpper(statusForContext(err))), nil
	}
	encoded, encodeErr := networkMap(record)
	if encodeErr != nil {
		return system.finish(result, started, domain.CollectionFailed, "ENCODE_FAILED"), nil
	}
	result.Records = []map[string]any{encoded}
	if len(warnings) == 0 && len(record.UnresolvedInodes) == 0 && record.Firewall.Status != domain.CollectionNotAvailable {
		result.Completeness = domain.CompletenessComplete
		return system.finish(result, started, domain.CollectionSuccess, ""), nil
	}
	result.Completeness = domain.CompletenessPartial
	return system.finish(result, started, domain.CollectionPartial, "PARTIAL_NETWORK"), nil
}

func readNetwork(ctx context.Context, view fileView) (networkRecord, []string, []string, error) {
	if err := ctx.Err(); err != nil {
		return networkRecord{}, nil, nil, err
	}
	inodePids, pidRefs, pidWarn := mapSocketInodes(ctx, view)
	sockets := make([]socketRecord, 0)
	refs := append([]string{}, pidRefs...)
	warnings := append([]string{}, pidWarn...)
	unresolved := make([]int64, 0)
	for _, spec := range []struct {
		path     string
		protocol string
		v6       bool
	}{
		{"proc/net/tcp", "tcp", false},
		{"proc/net/tcp6", "tcp6", true},
		{"proc/net/udp", "udp", false},
		{"proc/net/udp6", "udp6", true},
	} {
		raw, ref, warn, err := readText(ctx, view, spec.path)
		if isContext(err) {
			return networkRecord{}, refs, warnings, err
		}
		if ref != "" {
			refs = append(refs, ref)
		}
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		for _, sock := range parseSockets(raw, spec.protocol, spec.v6) {
			if pid, ok := inodePids[sock.Inode]; ok {
				sock.PID = pid
				sock.PIDResolved = true
			} else if sock.Inode > 0 {
				unresolved = append(unresolved, sock.Inode)
				warnings = append(warnings, "inode_unresolved")
			}
			sockets = append(sockets, sock)
		}
	}
	routeRaw, routeRef, routeWarn, err := readText(ctx, view, "proc/net/route")
	if isContext(err) {
		return networkRecord{}, refs, warnings, err
	}
	dnsRaw, dnsRef, dnsWarn, err := readText(ctx, view, "etc/resolv.conf")
	if isContext(err) {
		return networkRecord{}, refs, warnings, err
	}
	fw, fwRefs, fwWarn := readFirewall(view)
	refs = compactRefs(append(append(refs, routeRef, dnsRef), fwRefs...)...)
	warnings = compactRefs(append(append(warnings, routeWarn, dnsWarn), fwWarn...)...)
	return networkRecord{
		Sockets:          sockets,
		Routes:           parseRoutes(routeRaw),
		DNSNameservers:   parseNameservers(dnsRaw),
		Firewall:         fw,
		UnresolvedInodes: unresolved,
	}, refs, warnings, ctx.Err()
}

func mapSocketInodes(ctx context.Context, view fileView) (map[int64]int, []string, []string) {
	out := map[int64]int{}
	refs := make([]string, 0)
	warnings := make([]string, 0)
	pids, err := listProcPIDs(view)
	if err != nil {
		if !isContext(err) {
			warnings = append(warnings, "proc_unreadable")
		}
		return out, refs, warnings
	}
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return out, refs, warnings
		}
		fdDir := "proc/" + strconv.Itoa(pid) + "/fd"
		entries, dirErr := view.ReadDir(fdDir)
		if dirErr != nil {
			if isPermission(dirErr) {
				warnings = append(warnings, fdDir+"_permission_denied")
			}
			continue
		}
		for _, entry := range entries {
			link, linkErr := view.Readlink(fdDir + "/" + entry.Name())
			if linkErr != nil {
				continue
			}
			inode, ok := parseSocketLink(link)
			if !ok {
				continue
			}
			refs = append(refs, fdDir+"/"+entry.Name())
			if _, exists := out[inode]; !exists {
				out[inode] = pid
			}
		}
	}
	return out, compactRefs(refs...), compactRefs(warnings...)
}

func parseSocketLink(link string) (int64, bool) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
	inode, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

func parseSockets(raw, protocol string, v6 bool) []socketRecord {
	out := make([]socketRecord, 0)
	for i, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 10 {
			continue
		}
		local, okLocal := parseAddrPort(fields[1], v6)
		remote, okRemote := parseAddrPort(fields[2], v6)
		if !okLocal || !okRemote {
			continue
		}
		inode, _ := strconv.ParseInt(fields[9], 10, 64)
		state := tcpStates[strings.ToUpper(fields[3])]
		if protocol == "udp" || protocol == "udp6" {
			state = "UDP"
		}
		out = append(out, socketRecord{
			Protocol:      protocol,
			LocalAddress:  local,
			RemoteAddress: remote,
			State:         state,
			Inode:         inode,
			Listening:     state == "LISTEN",
		})
	}
	return out
}

func parseAddrPort(field string, v6 bool) (string, bool) {
	ipHex, portHex, ok := strings.Cut(field, ":")
	if !ok {
		return "", false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", false
	}
	ip, ok := decodeKernelIP(ipHex, v6)
	if !ok {
		return "", false
	}
	if v6 {
		return fmt.Sprintf("[%s]:%d", ip, port), true
	}
	return fmt.Sprintf("%s:%d", ip, port), true
}

func decodeKernelIP(raw string, v6 bool) (string, bool) {
	data, err := hex.DecodeString(raw)
	if err != nil {
		return "", false
	}
	if !v6 {
		if len(data) != 4 {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d.%d", data[3], data[2], data[1], data[0]), true
	}
	if len(data) != 16 {
		return "", false
	}
	// Linux stores IPv6 as four little-endian 32-bit words.
	parts := make([]string, 0, 8)
	for i := 0; i < 16; i += 4 {
		parts = append(parts, fmt.Sprintf("%02x%02x", data[i+3], data[i+2]))
		parts = append(parts, fmt.Sprintf("%02x%02x", data[i+1], data[i]))
	}
	return strings.Join(parts, ":"), true
}

func parseRoutes(raw string) []routeRecord {
	out := make([]routeRecord, 0)
	for i, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 8 {
			continue
		}
		dest, okDest := decodeKernelIP(fields[1], false)
		gw, okGW := decodeKernelIP(fields[2], false)
		mask, okMask := decodeKernelIP(fields[7], false)
		if !okDest || !okGW || !okMask {
			continue
		}
		out = append(out, routeRecord{Interface: fields[0], Destination: dest, Gateway: gw, Mask: mask})
	}
	return out
}

func parseNameservers(raw string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

func readFirewall(view fileView) (firewallRecord, []string, []string) {
	if data, err := view.ReadFile("proc/net/ip_tables_names"); err == nil {
		tables := compactRefs(strings.Fields(string(data))...)
		return firewallRecord{Status: "present", Tables: tables}, []string{"proc/net/ip_tables_names"}, nil
	}
	if _, err := view.Lstat("proc/net/nf_tables"); err == nil {
		return firewallRecord{Status: "present", Tables: []string{"nf_tables"}}, []string{"proc/net/nf_tables"}, nil
	}
	return firewallRecord{Status: domain.CollectionNotAvailable, Tables: []string{}}, nil, []string{"firewall_not_available"}
}

func networkMap(record networkRecord) (map[string]any, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}
