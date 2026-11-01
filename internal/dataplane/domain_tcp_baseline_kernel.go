package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"slices"
	"sync/atomic"
)

// Read-only output of the original held policy tool source. These bytes cannot
// issue a baseline owner, socket, flow, effect or cleanup permission.
type DomainTCPBaselineReadImage struct{ Rules, Routes, Links, Lookup []byte }
type DomainTCPBaselineReader interface {
	ReadDomainTCPBaseline(context.Context, netip.Addr, netip.Addr, string) (DomainTCPBaselineReadImage, error)
}

var ErrDomainTCPBaselineKernel = errors.New("original transparent TCP baseline kernel contract is unavailable")

type domainTCPBaselinePath struct {
	Ingress, Egress           string
	IngressIndex, EgressIndex int
	Gateway                   netip.Addr
}

// The initial supported path deliberately requires ordinary IPv4 routing,
// standard RPDB only, no NAT/CT-dependent peer hooks and no programmable link
// attachment. Unsupported router/VPN policy is observed and left untouched.
func domainTCPBaselineKernelContract(image DomainTCPBaselineReadImage, spec DomainPolicyTCPCaptureSpec) (domainTCPBaselinePath, error) {
	var zero domainTCPBaselinePath
	if !spec.valid() {
		return zero, ErrDomainTCPBaselineKernel
	}
	decode := func(raw []byte, out any) error {
		if len(raw) == 0 || len(raw) > 2<<20 || nfqws2ManagedUniqueJSON(raw) != nil {
			return ErrDomainTCPBaselineKernel
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
			return ErrDomainTCPBaselineKernel
		}
		return nil
	}
	var rules []struct {
		Priority int             `json:"priority"`
		Source   string          `json:"src"`
		Table    json.RawMessage `json:"table"`
		Protocol string          `json:"protocol,omitempty"`
	}
	if decode(image.Rules, &rules) != nil || len(rules) != 3 {
		return zero, ErrDomainTCPBaselineKernel
	}
	table := func(raw json.RawMessage, want string, number string) bool {
		return bytes.Equal(raw, []byte(`"`+want+`"`)) || bytes.Equal(raw, []byte(number))
	}
	for i, want := range []struct {
		priority int
		name, id string
	}{{0, "local", "255"}, {32766, "main", "254"}, {32767, "default", "253"}} {
		r := rules[i]
		if r.Priority != want.priority || r.Source != "all" || !table(r.Table, want.name, want.id) || r.Protocol != "" && r.Protocol != "kernel" {
			return zero, ErrDomainTCPBaselineKernel
		}
	}
	// Kernel link inspection is whole-namespace. Even an apparently unrelated
	// programmable bridge slave could transform the original pre-capture tuple.
	var links []map[string]json.RawMessage
	if decode(image.Links, &links) != nil || len(links) == 0 || len(links) > 256 {
		return zero, ErrDomainTCPBaselineKernel
	}
	indices := map[string]int{}
	up := map[string]bool{}
	peers := map[string]string{}
	for _, link := range links {
		for key := range link {
			if !slices.Contains([]string{"ifindex", "ifname", "link", "flags", "mtu", "qdisc", "operstate", "linkmode", "group", "txqlen", "link_type", "address", "broadcast", "linkinfo", "link_index", "link_netnsid", "promiscuity", "allmulti", "min_mtu", "max_mtu", "inet6_addr_gen_mode", "num_tx_queues", "num_rx_queues", "gso_max_size", "gso_max_segs", "tso_max_size", "tso_max_segs", "gro_max_size", "gso_ipv4_max_size", "gro_ipv4_max_size"}, key) {
				return zero, ErrDomainTCPBaselineKernel
			}
		}
		var name, qdisc string
		var index int
		if json.Unmarshal(link["ifname"], &name) != nil || json.Unmarshal(link["ifindex"], &index) != nil || index <= 0 || name == "" || indices[name] != 0 || json.Unmarshal(link["qdisc"], &qdisc) != nil || !slices.Contains([]string{"noqueue", "fq_codel", "pfifo_fast"}, qdisc) {
			return zero, ErrDomainTCPBaselineKernel
		}
		if len(link["xdp"]) != 0 || len(link["xdp_attached"]) != 0 || len(link["prog"]) != 0 {
			return zero, ErrDomainTCPBaselineKernel
		}
		if raw := link["linkinfo"]; len(raw) != 0 {
			var info struct {
				Kind string `json:"info_kind"`
			}
			if json.Unmarshal(raw, &info) != nil || info.Kind != "veth" {
				return zero, ErrDomainTCPBaselineKernel
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			if len(fields) != 1 {
				return zero, ErrDomainTCPBaselineKernel
			}
		}
		if raw := link["link"]; len(raw) != 0 {
			var peer string
			if json.Unmarshal(raw, &peer) != nil || !proxyFirewallInterface.MatchString(peer) || peer == name || peer == "lo" || len(link["linkinfo"]) == 0 {
				return zero, ErrDomainTCPBaselineKernel
			}
			peers[name] = peer
		}
		indices[name] = index
		var flags []string
		if json.Unmarshal(link["flags"], &flags) != nil {
			return zero, ErrDomainTCPBaselineKernel
		}
		up[name] = slices.Contains(flags, "UP") && slices.Contains(flags, "LOWER_UP")
	}
	for name, peer := range peers {
		// iproute2 exposes a same-namespace veth peer by name, rather than
		// link_index. This is link metadata only; require the complete reciprocal
		// pair, never interpret an arbitrary master/tunnel relationship as veth.
		if indices[peer] == 0 || peers[peer] != name || indices[peer] == indices[name] {
			return zero, ErrDomainTCPBaselineKernel
		}
	}
	if indices[spec.Client.Interface] == 0 || !up[spec.Client.Interface] {
		return zero, ErrDomainTCPBaselineKernel
	}
	var lookup []struct {
		Type        string          `json:"type,omitempty"`
		Destination string          `json:"dst"`
		Source      string          `json:"from"`
		Gateway     string          `json:"gateway,omitempty"`
		Device      string          `json:"dev"`
		Input       string          `json:"iif"`
		Table       json.RawMessage `json:"table,omitempty"`
		Flags       []string        `json:"flags,omitempty"`
		Cache       json.RawMessage `json:"cache,omitempty"`
		UID         *int            `json:"uid,omitempty"`
		Protocol    string          `json:"protocol,omitempty"`
		Scope       string          `json:"scope,omitempty"`
	}
	if decode(image.Lookup, &lookup) != nil || len(lookup) != 1 {
		return zero, ErrDomainTCPBaselineKernel
	}
	route := lookup[0]
	if route.Type != "" && route.Type != "unicast" || route.Destination != spec.Xray.RealIP.String() || route.Source != spec.Client.Address.String() || route.Input != spec.Client.Interface || route.Device == spec.Client.Interface || route.Device == "lo" || indices[route.Device] == 0 || !up[route.Device] || len(route.Flags) != 0 || len(route.Table) != 0 && !table(route.Table, "main", "254") || route.UID != nil || len(route.Cache) != 0 && !bytes.Equal(route.Cache, []byte("[]")) {
		return zero, ErrDomainTCPBaselineKernel
	}
	gateway := netip.Addr{}
	if route.Gateway != "" {
		var err error
		gateway, err = netip.ParseAddr(route.Gateway)
		if err != nil || !gateway.Is4() || !gateway.IsGlobalUnicast() || gateway.IsLoopback() {
			return zero, ErrDomainTCPBaselineKernel
		}
	}
	// Whole route coverage is required even though the exact forwarded lookup
	// supplies the selected path. Encapsulation, nexthop groups and alternate
	// tables could otherwise escape the initial deliberately small contract.
	var routes []map[string]json.RawMessage
	if decode(image.Routes, &routes) != nil || len(routes) == 0 || len(routes) > 1024 {
		return zero, ErrDomainTCPBaselineKernel
	}
	local := false
	for _, r := range routes {
		for key := range r {
			if !slices.Contains([]string{"type", "dst", "gateway", "dev", "protocol", "scope", "prefsrc", "metric", "table", "flags", "pref"}, key) {
				return zero, ErrDomainTCPBaselineKernel
			}
		}
		for _, key := range []string{"encap", "nhid", "nexthops", "multipath", "via"} {
			if len(r[key]) != 0 {
				return zero, ErrDomainTCPBaselineKernel
			}
		}
		if raw := r["table"]; len(raw) != 0 && !table(raw, "main", "254") && !table(raw, "local", "255") {
			return zero, ErrDomainTCPBaselineKernel
		}
		var kind, destination, device string
		if len(r["type"]) != 0 && json.Unmarshal(r["type"], &kind) != nil || json.Unmarshal(r["dst"], &destination) != nil || json.Unmarshal(r["dev"], &device) != nil {
			return zero, ErrDomainTCPBaselineKernel
		}
		if kind != "" && kind != "unicast" && kind != "local" && kind != "broadcast" {
			return zero, ErrDomainTCPBaselineKernel
		}
		if device == "" || indices[device] == 0 {
			return zero, ErrDomainTCPBaselineKernel
		}
		if kind == "local" && destination == spec.Listen.Addr().String() && device == spec.Client.Interface {
			local = true
		}
	}
	if !local {
		return zero, ErrDomainTCPBaselineKernel
	}
	return domainTCPBaselinePath{Ingress: spec.Client.Interface, Egress: route.Device, IngressIndex: indices[spec.Client.Interface], EgressIndex: indices[route.Device], Gateway: gateway}, nil
}

type domainTCPBaselineKernelOwner struct {
	self     *domainTCPBaselineKernelOwner
	capture  *domainTCPCaptureExecutionResource
	baseline *syntheticBaselineExecutionResource
	reader   DomainTCPBaselineReader
	path     domainTCPBaselinePath
	flow     atomic.Pointer[domainTCPBaselineExecutionResource]
}

func newDomainTCPBaselineKernelOwner(ctx context.Context, capture *domainTCPCaptureExecutionResource, baseline *syntheticBaselineExecutionResource) (*domainTCPBaselineKernelOwner, error) {
	if capture == nil || capture.self != capture || capture.tools == nil || !capture.tools.valid() || !filepath.IsAbs(capture.tools.IP) || filepath.Clean(capture.tools.IP) != capture.tools.IP || baseline == nil || baseline.self != baseline || baseline.capture != capture.capture || baseline.mapping != capture.mapping || baseline.tools != capture.tools || baseline.backend != capture.backend {
		return nil, ErrDomainTCPBaselineKernel
	}
	reader, ok := capture.tools.Runner.(DomainTCPBaselineReader)
	if !ok {
		return nil, ErrDomainTCPBaselineKernel
	}
	r := &domainTCPBaselineKernelOwner{capture: capture, baseline: baseline, reader: reader}
	r.self = r
	var path domainTCPBaselinePath
	err := capture.process.withCurrentFileObservation(ctx, func(files *xrayDomainTCPFileObservation) error {
		var observeErr error
		path, observeErr = r.observeWithFiles(ctx, files)
		return observeErr
	})
	if err != nil {
		return nil, err
	}
	r.path = path
	return r, nil
}

func (r *domainTCPBaselineKernelOwner) sources(ctx context.Context) error {
	return r.sourcesWithFiles(ctx, nil)
}
func (r *domainTCPBaselineKernelOwner) sourcesWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) error {
	if r == nil || r.self != r || r.capture == nil || r.baseline == nil || r.reader == nil || r.capture.tools == nil || !sameNetworkPolicyDependency(r.reader, r.capture.tools.Runner) || r.baseline.capture != r.capture.capture || r.baseline.mapping != r.capture.mapping {
		return ErrDomainTCPBaselineKernel
	}
	if err := r.capture.checkPreparedWithFiles(ctx, files); err != nil {
		return err
	}
	return r.baseline.currentBaselineWithFiles(ctx, files)
}

func (r *domainTCPBaselineKernelOwner) observe(ctx context.Context) (domainTCPBaselinePath, error) {
	return r.observeWithFiles(ctx, nil)
}
func (r *domainTCPBaselineKernelOwner) observeWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) (domainTCPBaselinePath, error) {
	var path domainTCPBaselinePath
	if err := r.sourcesWithFiles(ctx, files); err != nil {
		return path, err
	}
	spec := r.capture.definition.Process.Capture
	for pass := 0; pass < 2; pass++ {
		if err := domainTCPBaselineForwarding(ctx, r.capture.process.scope.networkIdentity); err != nil {
			return path, fmt.Errorf("domain TCP baseline native forwarding/programs: %w", err)
		}
		image, err := r.reader.ReadDomainTCPBaseline(ctx, spec.Client.Address, spec.Xray.RealIP, spec.Client.Interface)
		if err != nil {
			return path, fmt.Errorf("domain TCP baseline original route read: %w", err)
		}
		view, err := r.capture.readWithFiles(ctx, files)
		if err != nil {
			return path, err
		}
		if flow := r.flow.Load(); flow != nil {
			image, view.Rows, err = flow.counterfactual(ctx, image, view.Rows)
			if err != nil {
				return path, err
			}
		}
		current, err := domainTCPBaselineKernelContract(image, spec)
		if err != nil {
			return path, fmt.Errorf("domain TCP baseline routing contract: %w", err)
		}
		if pass != 0 && current != path {
			return path, ErrDomainTCPBaselineKernel
		}
		path = current
		if err := domainTCPBaselineNoPeerEffects(view.Rows, r.capture.effects, r.baseline.effects); err != nil {
			return path, fmt.Errorf("domain TCP baseline packet-hook contract: %w", err)
		}
		if pass == 0 {
			if err := r.sourcesWithFiles(ctx, files); err != nil {
				return path, err
			}
		}
	}
	return path, r.capture.registered(ctx) // Local original-owner bookend only.
}

func (r *domainTCPBaselineKernelOwner) Current(ctx context.Context) error {
	return r.currentWithFiles(ctx, nil)
}
func (r *domainTCPBaselineKernelOwner) currentWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) error {
	path, err := r.observeWithFiles(ctx, files)
	if err != nil {
		return err
	}
	if path != r.path {
		return ErrDomainTCPBaselineKernel
	}
	return nil
}

func domainTCPBaselineNoPeerEffects(rows []backendInventoryRow, capture, baseline PolicyEffectPlan) error {
	if domainTCPCapturePreparedInventory(rows, capture) != nil {
		return ErrDomainTCPBaselineKernel
	}
	if _, err := syntheticBaselineTupleFromPlan(baseline); err != nil {
		return ErrDomainTCPBaselineKernel
	}
	filtered, err := domainTCPCaptureBaselineRows(rows, capture)
	if err != nil {
		return err
	}
	for index := range baseline.Effects {
		count, err := syntheticBaselineExactPresence(filtered, baseline, index)
		if err != nil || count != 1 {
			return ErrDomainTCPBaselineKernel
		}
	}
	chain := baseline.Effects[0].Add[3]
	forward := false
	for _, row := range filtered {
		if row.Family != 4 && row.Family != 6 || !slices.Contains([]string{"raw", "mangle", "nat", "filter", "security"}, row.Table) {
			return ErrDomainTCPBaselineKernel
		}
		t := row.Tokens
		owned := len(t) > 1 && t[1] == chain
		for n := 2; n+1 < len(t); n++ {
			if t[n] == "-j" && t[n+1] == chain {
				owned = true
			}
		}
		if owned {
			continue
		} // Whole exact acknowledged baseline was checked above.
		if len(t) != 3 || t[0] != "-P" || t[2] != "ACCEPT" {
			return ErrDomainTCPBaselineKernel
		}
		allowed := map[string][]string{"raw": {"PREROUTING", "OUTPUT"}, "mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}, "nat": {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"}, "filter": {"INPUT", "FORWARD", "OUTPUT"}, "security": {"INPUT", "FORWARD", "OUTPUT"}}
		if !slices.Contains(allowed[row.Table], t[1]) {
			return ErrDomainTCPBaselineKernel
		}
		if row.Family == 4 && row.Table == "filter" && t[1] == "FORWARD" {
			forward = true
		}
	}
	if !forward {
		return ErrDomainTCPBaselineKernel
	}
	return nil
}
