package dataplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/netresolve"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"golang.org/x/crypto/curve25519"
)

var ErrWGEndpointChanged = errors.New("WireGuard endpoint DNS or WAN path changed; a fresh candidate transaction is required")

// WGEndpointResolver returns the expiry of the complete DNS answer, including
// CNAMEs. A zero expiry means no cache authority: revalidate before every start.
type WGEndpointResolver func(context.Context, string) ([]netip.Addr, time.Time, error)

// WGEndpointState is private cleanup authority bound to RuntimeConfigSHA256.
// It grants exactly one marked host route and rule, never a global exclusion.
type WGEndpointState struct {
	Original   string    `json:"original"`
	Endpoint   string    `json:"endpoint"`
	ResolvedAt time.Time `json:"resolved_at"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Device     string    `json:"device"`
	Gateway    string    `json:"gateway,omitempty"`
	Source     string    `json:"source"`
	Priority   int       `json:"priority"`
	Mark       uint32    `json:"mark"`
	Table      int       `json:"table"`
	Metric     int       `json:"metric"`
}

func (e WGEndpointState) address() netip.Addr {
	host, _, _ := net.SplitHostPort(e.Endpoint)
	addr, _ := netip.ParseAddr(host)
	return addr
}
func (e WGEndpointState) prefix() string {
	addr := e.address()
	return netip.PrefixFrom(addr, addr.BitLen()).String()
}
func (e WGEndpointState) args(args ...string) []string {
	return canaryFamilyArgs(canarySourceFamily(e.address()), args...)
}

func (a *WARPWireGuardAdapter) endpointSpec() (PolicyOwnershipSpec, error) {
	for _, spec := range PolicyOwnershipSpecs() {
		if spec.Adapter == a.ID() && spec.Interface == a.interfaceName() && spec.Table == a.table() && spec.PriorityBase == a.priorityBase() && spec.EndpointMark != 0 {
			return spec, nil
		}
	}
	return PolicyOwnershipSpec{}, errors.New("WireGuard endpoint ownership coordinates are unavailable")
}

func (a *WARPWireGuardAdapter) endpointNow() time.Time {
	if a.EndpointNow != nil {
		return a.EndpointNow().UTC()
	}
	return time.Now().UTC()
}

func (a *WARPWireGuardAdapter) resolveWGEndpoint(ctx context.Context, endpoint string) ([]netip.Addr, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, time.Time{}, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !publicfetch.PublicAddress(addr) {
			return nil, time.Time{}, errors.New("WireGuard endpoint is non-public")
		}
		return []netip.Addr{addr.Unmap()}, time.Time{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var addresses []netip.Addr
	var expiry time.Time
	if a.EndpointResolver != nil {
		addresses, expiry, err = a.EndpointResolver(ctx, host)
	} else if a.Resolver != nil {
		addresses, err = a.Resolver(ctx, host)
	} else {
		addresses, err = netresolve.LookupNetIP(ctx, "ip", host)
	}
	// An injected/platform callback can finish after cancellation. Its answer
	// cannot authorize endpoint staging or refresh an existing DNS lease.
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	if err != nil || len(addresses) == 0 || len(addresses) > 32 {
		return nil, time.Time{}, errors.New("WireGuard endpoint resolution unavailable or exceeds limit")
	}
	for _, addr := range addresses {
		if !publicfetch.PublicAddress(addr) {
			return nil, time.Time{}, errors.New("WireGuard endpoint resolved to a non-public address")
		}
	}
	if !expiry.IsZero() && !expiry.After(a.endpointNow()) {
		return nil, time.Time{}, errors.New("WireGuard endpoint DNS answer already expired")
	}
	if expiry.After(a.endpointNow().Add(24 * time.Hour)) {
		expiry = a.endpointNow().Add(24 * time.Hour)
	}
	return addresses, expiry, nil
}

func (a *WARPWireGuardAdapter) stageWGEndpoint(ctx context.Context, profile string) (string, *WGEndpointState, error) {
	endpoint, err := wgEndpoint(profile)
	if err != nil {
		return "", nil, err
	}
	addresses, expiry, err := a.resolveWGEndpoint(ctx, endpoint)
	if err != nil {
		return "", nil, err
	}
	chosen := addresses[0].Unmap()
	for _, addr := range addresses {
		if addr.Unmap().Is4() {
			chosen = addr.Unmap()
			break
		}
	}
	_, port, _ := net.SplitHostPort(endpoint)
	spec, err := a.endpointSpec()
	if err != nil {
		return "", nil, err
	}
	e := &WGEndpointState{Original: endpoint, Endpoint: net.JoinHostPort(chosen.String(), port), ResolvedAt: a.endpointNow(), ExpiresAt: expiry, Priority: spec.EndpointPriority, Mark: spec.EndpointMark, Table: spec.Table, Metric: 1}
	if err := a.readWGEndpointWAN(ctx, e); err != nil {
		return "", nil, err
	}
	pinned, err := replaceWGEndpoint([]byte(profile), e.Endpoint)
	return string(pinned), e, err
}

type wgEndpointRoute struct {
	Destination    string          `json:"dst"`
	From           string          `json:"from,omitempty"`
	Gateway        string          `json:"gateway"`
	Device         string          `json:"dev"`
	Source         string          `json:"prefsrc"`
	SelectedSource string          `json:"src"`
	Table          json.RawMessage `json:"table,omitempty"`
	Type           string          `json:"type"`
	Flags          []string        `json:"flags"`
	Metric         int             `json:"metric"`
	Protocol       string          `json:"protocol,omitempty"`
	Scope          string          `json:"scope,omitempty"`
}

// -N is mandatory for table authority and also makes protocol/scope numeric.
// Normalize only exact enum values, retaining foreign values for rejection.
func wgEndpointRouteEnum(raw json.RawMessage, names map[uint8]string) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if string(raw) == "null" {
		return "", errors.New("null route enum")
	}
	var label string
	if json.Unmarshal(raw, &label) == nil {
		if label == "" {
			return "", errors.New("empty route enum")
		}
		id, err := strconv.ParseUint(label, 10, 8)
		if err != nil {
			return label, nil
		}
		if strconv.FormatUint(id, 10) != label {
			return "", errors.New("noncanonical route enum")
		}
		if name, ok := names[uint8(id)]; ok {
			return name, nil
		}
		return label, nil
	}
	var id uint8
	if json.Unmarshal(raw, &id) != nil || string(raw) != strconv.FormatUint(uint64(id), 10) {
		return "", errors.New("invalid numeric route enum")
	}
	if name, ok := names[id]; ok {
		return name, nil
	}
	return strconv.Itoa(int(id)), nil
}

func (r *wgEndpointRoute) UnmarshalJSON(data []byte) error {
	type plain wgEndpointRoute
	var out plain
	wire := struct {
		*plain
		Protocol json.RawMessage `json:"protocol"`
		Scope    json.RawMessage `json:"scope"`
	}{plain: &out}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	var err error
	out.Protocol, err = wgEndpointRouteEnum(wire.Protocol, map[uint8]string{2: "kernel", 3: "boot", 4: "static", 9: "ra", 16: "dhcp"})
	if err != nil {
		return err
	}
	out.Scope, err = wgEndpointRouteEnum(wire.Scope, map[uint8]string{0: "global", 200: "site", 253: "link", 254: "host"})
	if err != nil {
		return err
	}
	*r = wgEndpointRoute(out)
	return nil
}

// iproute2 can encode the same table ID as a JSON number or decimal string.
// Compare IDs without treating arbitrary table names as equivalent authority.
func wgEndpointTableMatches(raw json.RawMessage, expected int) bool {
	if expected < 1 || uint64(expected) > 1<<32-1 || len(raw) == 0 || len(raw) > 32 {
		return false
	}
	var number uint32
	if err := json.Unmarshal(raw, &number); err == nil {
		return uint64(number) == uint64(expected)
	}
	var label string
	if err := json.Unmarshal(raw, &label); err != nil {
		return false
	}
	if label == "main" {
		return expected == 254
	}
	id, err := strconv.ParseUint(label, 10, 32)
	return err == nil && strconv.FormatUint(id, 10) == label && id == uint64(expected)
}

func parseWGEndpointRoutes(data []byte) ([]wgEndpointRoute, error) {
	if len(data) > 64<<10 {
		return nil, errors.New("WireGuard endpoint route response exceeds bound")
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil || len(raw) > 1 {
		return nil, errors.New("WireGuard endpoint route is invalid or ambiguous")
	}
	allowed := map[string]bool{"dst": true, "from": true, "gateway": true, "dev": true, "prefsrc": true, "src": true, "table": true, "type": true, "flags": true, "protocol": true, "scope": true, "metric": true, "pref": true, "uid": true, "cache": true}
	for _, route := range raw {
		for key := range route {
			if !allowed[key] {
				return nil, errors.New("WireGuard endpoint route contains unsupported attributes")
			}
		}
	}
	var routes []wgEndpointRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, err
	}
	for i, route := range routes {
		if route.Type != "" && route.Type != "unicast" {
			return nil, errors.New("WireGuard endpoint route is not unicast")
		}
		if _, present := raw[i]["from"]; present && !wgEndpointUnrestrictedSource(route.From, route.Destination) {
			return nil, errors.New("WireGuard endpoint route has a restricted or invalid source selector")
		}
	}
	return routes, nil
}

// IPv6 route-get normally reports from:"::". Accept only a well-formed
// unrestricted selector of the destination's family; a source-specific route
// cannot authorize our source-independent endpoint pin or its cleanup.
func wgEndpointUnrestrictedSource(from, destination string) bool {
	source, err := netip.ParseAddr(from)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(from)
		if prefixErr != nil || prefix.Bits() != 0 {
			return false
		}
		source = prefix.Addr()
	}
	dst, err := netip.ParseAddr(destination)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(destination)
		if prefixErr != nil {
			return false
		}
		dst = prefix.Addr()
	}
	return source.IsUnspecified() && source.Zone() == "" && dst.Zone() == "" && source.Is4() == dst.Is4()
}

func (a *WARPWireGuardAdapter) readWGEndpointWAN(ctx context.Context, e *WGEndpointState) error {
	data, err := a.run(ctx, a.ip(), e.args("-j", "route", "get", e.address().String(), "mark", "0")...)
	if err != nil {
		return errors.New("WireGuard endpoint WAN route inspection failed")
	}
	routes, err := parseWGEndpointRoutes(data)
	if err != nil {
		return fmt.Errorf("WireGuard endpoint WAN route inspection is invalid: %w", err)
	}
	if len(routes) != 1 {
		return errors.New("WireGuard endpoint WAN route is not unique")
	}
	route := routes[0]
	if route.Source == "" {
		route.Source = route.SelectedSource
	}
	if len(route.Table) != 0 && !wgEndpointTableMatches(route.Table, 254) {
		return errors.New("WireGuard endpoint bootstrap route must use main")
	}
	if route.Device == "" || route.Device == "lo" || strings.HasPrefix(route.Device, "rz-") || strings.ContainsAny(route.Device, " \t\n/\\") || len(route.Device) > 15 || len(route.Flags) != 0 {
		return errors.New("WireGuard endpoint WAN device is invalid")
	}
	source, err := netip.ParseAddr(route.Source)
	if err != nil || source.Is4() != e.address().Is4() || !source.IsGlobalUnicast() {
		return errors.New("WireGuard endpoint WAN source is unavailable")
	}
	if route.Gateway != "" {
		gateway, err := netip.ParseAddr(route.Gateway)
		if err != nil || gateway.Is4() != source.Is4() || gateway.IsMulticast() || gateway.IsUnspecified() {
			return errors.New("WireGuard endpoint gateway is invalid")
		}
	}
	e.Device, e.Gateway, e.Source = route.Device, route.Gateway, route.Source
	return nil
}

func (a *WARPWireGuardAdapter) validWGEndpoint(e *WGEndpointState, runtime []byte) error {
	if e == nil {
		return nil
	} // Old committed states retain legacy cleanup only.
	spec, err := a.endpointSpec()
	if err != nil {
		return err
	}
	endpoint, err := wgEndpoint(string(runtime))
	if err != nil || endpoint != e.Endpoint || !publicfetch.PublicAddress(e.address()) || e.Priority != spec.EndpointPriority || e.Mark != spec.EndpointMark || e.Table != spec.Table || e.Metric != 1 || e.ResolvedAt.IsZero() || e.Device == "" || e.Device == "lo" || strings.HasPrefix(e.Device, "rz-") || len(e.Device) > 15 || strings.ContainsAny(e.Device, " \t\r\n/\\") {
		return errors.New("WireGuard endpoint receipt does not match runtime ownership")
	}
	host, port, err := net.SplitHostPort(e.Original)
	_, pinnedPort, _ := net.SplitHostPort(e.Endpoint)
	if err != nil || host == "" || port != pinnedPort {
		return errors.New("WireGuard original endpoint receipt is invalid")
	}
	if !e.ExpiresAt.IsZero() && (!e.ExpiresAt.After(e.ResolvedAt) || e.ExpiresAt.After(e.ResolvedAt.Add(24*time.Hour))) {
		return errors.New("WireGuard endpoint expiry is invalid")
	}
	source, err := netip.ParseAddr(e.Source)
	if err != nil || !source.IsGlobalUnicast() || source.Is4() != e.address().Is4() {
		return errors.New("WireGuard endpoint source receipt is invalid")
	}
	if e.Gateway != "" {
		gateway, err := netip.ParseAddr(e.Gateway)
		if err != nil || gateway.Is4() != source.Is4() || gateway.IsMulticast() || gateway.IsUnspecified() {
			return errors.New("WireGuard endpoint gateway receipt is invalid")
		}
	}
	return nil
}

// Validate expiry and current WAN before recovery or activation. No changed
// DNS/WAN answer can silently replace the reviewed candidate or expand scope.
func (a *WARPWireGuardAdapter) revalidateWGEndpoint(ctx context.Context, e *WGEndpointState) error {
	if e == nil {
		return nil
	}
	current := *e
	host, _, _ := net.SplitHostPort(e.Original)
	_, literalErr := netip.ParseAddr(host)
	if literalErr != nil && (e.ExpiresAt.IsZero() || a.endpointNow().Before(e.ResolvedAt) || !a.endpointNow().Before(e.ExpiresAt)) {
		addresses, expiry, err := a.resolveWGEndpoint(ctx, e.Original)
		if err != nil {
			return err
		}
		found := false
		for _, addr := range addresses {
			found = found || addr.Unmap() == e.address()
		}
		if !found {
			return ErrWGEndpointChanged
		}
		current.ResolvedAt, current.ExpiresAt = a.endpointNow(), expiry
	}
	if err := a.readWGEndpointWAN(ctx, &current); err != nil {
		return err
	}
	if current.Device != e.Device || current.Gateway != e.Gateway || current.Source != e.Source {
		return ErrWGEndpointChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	*e = current // publish a new lease only after the WAN check also succeeds
	return nil
}

func (e WGEndpointState) ruleArgs(action string) []string {
	return e.args("rule", action, "priority", strconv.Itoa(e.Priority), "to", e.prefix(), "fwmark", fmt.Sprintf("0x%x/0xffffffff", e.Mark), "lookup", strconv.Itoa(e.Table))
}
func (e WGEndpointState) routeArgs(action string) []string {
	args := []string{"route", action, e.prefix()}
	if e.Gateway != "" {
		args = append(args, "via", e.Gateway)
	}
	args = append(args, "dev", e.Device)
	if e.Gateway != "" {
		args = append(args, "onlink")
	}
	args = append(args, "src", e.Source, "proto", "static", "metric", strconv.Itoa(e.Metric), "table", strconv.Itoa(e.Table))
	return e.args(args...)
}

func (e WGEndpointState) matchesRule(family int, line string) bool {
	if (family != 4 && family != 6) || len(line) > 2048 || strings.ContainsAny(line, "\x00\r\n") {
		return false
	}
	fields := strings.Fields(line)
	if (family == 4) != e.address().Is4() || len(fields) != 9 || fields[0] != strconv.Itoa(e.Priority)+":" {
		return false
	}
	values := map[string]string{}
	for i := 1; i < len(fields); i += 2 {
		if values[fields[i]] != "" {
			return false
		}
		values[fields[i]] = fields[i+1]
	}
	if values["from"] != "all" || values["lookup"] != strconv.Itoa(e.Table) {
		return false
	}
	dest, err := netip.ParsePrefix(values["to"])
	if err != nil {
		addr, x := netip.ParseAddr(values["to"])
		if x != nil {
			return false
		}
		dest = netip.PrefixFrom(addr, addr.BitLen())
	}
	if dest.String() != e.prefix() {
		return false
	}
	markText, maskText, masked := strings.Cut(values["fwmark"], "/")
	mark, err := strconv.ParseUint(markText, 0, 32)
	if err != nil || uint32(mark) != e.Mark {
		return false
	}
	if masked {
		mask, err := strconv.ParseUint(maskText, 0, 32)
		if err != nil || mask != 0xffffffff {
			return false
		}
	}
	return true
}

func (a *WARPWireGuardAdapter) inspectWGEndpoint(ctx context.Context, e *WGEndpointState) (routePresent, rulePresent bool, retErr error) {
	family := 4
	if e.address().Is6() {
		family = 6
	}
	lines, err := readPolicyRules(ctx, a.Runner, a.ip(), family)
	if err != nil {
		return false, false, err
	}
	for _, line := range lines {
		priority, ok := policyLinePriority(line)
		if !ok {
			return false, false, errors.New("unrecognized endpoint rule")
		}
		if priority == e.Priority {
			if rulePresent || !e.matchesRule(family, line) {
				return false, false, errors.New("WireGuard endpoint priority has foreign or duplicate rule")
			}
			rulePresent = true
		}
		if priority > 0 && priority < e.Priority && policyLineMayOverlap(line, kernelPolicyRule{family: family, source: "all", destination: e.prefix()}) {
			return false, false, errors.New("earlier foreign rule may intercept WireGuard endpoint")
		}
	}
	data, err := a.run(ctx, a.ip(), e.args("-j", "route", "show", "table", strconv.Itoa(e.Table), "exact", e.prefix())...)
	if err != nil && strings.Contains(string(data), "FIB table does not exist") {
		data = []byte("[]")
		err = nil
	}
	if err != nil {
		return false, false, err
	}
	routes, err := parseWGEndpointRoutes(data)
	if err != nil {
		return false, false, err
	}
	if len(routes) == 0 {
		return false, rulePresent, nil
	}
	r := routes[0]
	flagsOK := len(r.Flags) == 0 && e.Gateway == "" || len(r.Flags) == 1 && r.Flags[0] == "onlink" && e.Gateway != ""
	destination := r.Destination
	if addr, err := netip.ParseAddr(destination); err == nil {
		destination = netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	scopeOK := r.Scope == "" || e.Gateway == "" && r.Scope == "link" || e.Gateway != "" && (r.Scope == "global" || r.Scope == "universe")
	if destination != e.prefix() || r.Device != e.Device || r.Gateway != e.Gateway || r.Source != e.Source || r.Metric != e.Metric || r.Protocol != "static" || !scopeOK || !flagsOK || len(r.Table) != 0 && !wgEndpointTableMatches(r.Table, e.Table) {
		return false, false, errors.New("WireGuard endpoint route has a foreign tuple")
	}
	return true, rulePresent, nil
}

func (a *WARPWireGuardAdapter) installWGEndpoint(ctx context.Context, e *WGEndpointState) (retErr error) {
	if e == nil {
		return nil
	}
	route, rule, err := a.inspectWGEndpoint(ctx, e)
	if err != nil {
		return err
	}
	if route || rule {
		return errors.New("WireGuard endpoint resources already occupied")
	}
	if _, err = a.run(ctx, a.ip(), e.routeArgs("add")...); err != nil {
		return err
	}
	routeAdded, ruleAdded := true, false
	defer func() {
		if retErr != nil {
			cleanup, cancel := context.WithTimeout(wgNamedCleanupContext(context.WithoutCancel(ctx)), 8*time.Second)
			defer cancel()
			if ruleAdded {
				_, err := a.run(cleanup, a.ip(), e.ruleArgs("del")...)
				retErr = errors.Join(retErr, err)
			}
			if routeAdded {
				_, err := a.run(cleanup, a.ip(), e.routeArgs("del")...)
				retErr = errors.Join(retErr, err)
			}
		}
	}()
	if _, err = a.run(ctx, a.ip(), e.ruleArgs("add")...); err != nil {
		return err
	}
	ruleAdded = true
	route, rule, err = a.inspectWGEndpoint(ctx, e)
	if err != nil {
		return err
	}
	if !route || !rule {
		return errors.New("WireGuard endpoint readback incomplete")
	}
	return nil
}

func (a *WARPWireGuardAdapter) removeWGEndpoint(ctx context.Context, e *WGEndpointState) error {
	ctx = wgNamedCleanupContext(ctx)
	if e == nil {
		return nil
	}
	route, rule, err := a.inspectWGEndpoint(ctx, e)
	if err != nil {
		return err
	}
	if rule {
		if _, err = a.run(ctx, a.ip(), e.ruleArgs("del")...); err != nil {
			return err
		}
	}
	if route {
		if _, err = a.run(ctx, a.ip(), e.routeArgs("del")...); err != nil {
			return err
		}
	}
	route, rule, err = a.inspectWGEndpoint(ctx, e)
	if err != nil {
		return err
	}
	if route || rule {
		return errors.New("WireGuard endpoint cleanup unconfirmed")
	}
	return nil
}

func (a *WARPWireGuardAdapter) verifyWGEndpoint(ctx context.Context, e *WGEndpointState) error {
	if e == nil {
		return nil
	}
	route, rule, err := a.inspectWGEndpoint(ctx, e)
	if err != nil {
		return err
	}
	if !route || !rule {
		return errors.New("WireGuard endpoint pin is missing")
	}
	return a.verifyWGInterfaceIdentity(ctx, e)
}

func wgRuntimePublicKey(profile []byte) (string, error) {
	section, privateText := "", ""
	interfaceSeen, privateSeen := false, false
	for _, line := range strings.Split(string(profile), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "Interface" {
				if interfaceSeen {
					return "", errors.New("runtime identity is ambiguous")
				}
				interfaceSeen = true
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "PrivateKey") {
			continue
		}
		if section != "Interface" || privateSeen {
			return "", errors.New("runtime identity is ambiguous")
		}
		privateText, privateSeen = strings.TrimSpace(value), true
	}
	if !privateSeen {
		return "", errors.New("runtime identity unavailable")
	}
	private, err := base64.StdEncoding.Strict().DecodeString(privateText)
	if err != nil || len(private) != 32 {
		return "", errors.New("invalid runtime key")
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	clear(private)
	if err != nil {
		return "", errors.New("derive runtime public identity failed")
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

func (a *WARPWireGuardAdapter) verifyWGInterfaceIdentity(ctx context.Context, e *WGEndpointState) error {
	if e == nil {
		return nil
	}
	active, err := a.deactivationInterfaceActive(ctx)
	if err != nil || !active {
		return err
	}
	expected, err := wgRuntimePublicKey(mustRead(a.RuntimeConfigPath))
	if err != nil {
		return err
	}
	actual, err := a.run(ctx, a.wg(), "show", a.interfaceName(), "public-key")
	if err != nil || strings.TrimSpace(string(actual)) != expected {
		return errors.New("WireGuard interface public identity differs from owned runtime; retained for review")
	}
	mark, err := a.run(ctx, a.wg(), "show", a.interfaceName(), "fwmark")
	value, parseErr := strconv.ParseUint(strings.TrimSpace(string(mark)), 0, 32)
	if err != nil || parseErr != nil || uint32(value) != e.Mark {
		return errors.New("WireGuard endpoint socket mark is not confirmed")
	}
	return nil
}
