//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/commandrun"
)

// This private priority is confined to the newly created native router netns.
// Its ephemeral, ACK-only cleanup grant is a fixture mechanism, not production
// policy receipt, lease, cold Apply or recovery acceptance.
const nativeRouterHTTPSPriority = 22949

func nativeScopedXrayFixtureExtraBudget() time.Duration {
	if os.Getenv("RAZVILKA_XRAY_ROUTER_HTTPS_NATIVE") == "1" {
		return 40 * time.Second
	}
	return 0
}

type nativeRouterHTTPSLease struct {
	ip        string
	request   nodeRouterHTTPSRequest
	table     int
	namespace string
	guard     func(context.Context) error
	added     bool
	unknown   bool
}

func (l *nativeRouterHTTPSLease) command(ctx context.Context, args ...string) ([]byte, error) {
	namespace, err := nativeRouterHTTPSNamespace()
	if err != nil || namespace != l.namespace {
		return nil, errors.Join(errors.New("router HTTPS fixture namespace identity changed"), err)
	}
	return commandrun.Output(ctx, 2*time.Second, 64<<10, l.ip, args...)
}

func nativeRouterHTTPSNamespace() (string, error) {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return "", err
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil || len(self) > 64 || len(init) > 64 || self == init ||
		!strings.HasPrefix(self, "net:[") || !strings.HasPrefix(init, "net:[") {
		return "", errors.Join(errors.New("router HTTPS fixture must have a different network namespace from PID 1"), err)
	}
	return self, nil
}

func (l *nativeRouterHTTPSLease) mutation(verb string) []string {
	return []string{"-4", "rule", verb, "priority", strconv.Itoa(nativeRouterHTTPSPriority),
		"from", l.request.Source.String() + "/32", "to", l.request.Destination.String() + "/32",
		"oif", l.request.Interface, "lookup", strconv.Itoa(l.table)}
}

func nativeRouterHTTPSHost(value string, expected netip.Addr) bool {
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		return prefix.Bits() == 32 && prefix.Addr() == expected
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address == expected
}

// Accept only this fixture's exact tuple; another tuple at the private slot or
// the same tuple at another slot is a collision, never deletion authority.
func (l *nativeRouterHTTPSLease) count(ctx context.Context) (int, error) {
	output, err := l.command(ctx, "-N", "-4", "rule", "show")
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 4096 {
		return 0, errors.New("fixture RPDB inventory exceeded its bound")
	}
	count := 0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 || len(line) > 1024 || !strings.HasSuffix(fields[0], ":") {
			return 0, errors.New("fixture RPDB inventory is unavailable")
		}
		priority, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil {
			return 0, err
		}
		exact := len(fields) == 9 && fields[1] == "from" && nativeRouterHTTPSHost(fields[2], l.request.Source) &&
			fields[3] == "to" && nativeRouterHTTPSHost(fields[4], l.request.Destination) &&
			fields[5] == "oif" && fields[6] == l.request.Interface && fields[7] == "lookup" && fields[8] == strconv.Itoa(l.table)
		if priority == nativeRouterHTTPSPriority {
			if !exact {
				return 0, errors.New("foreign tuple occupies the fixture RPDB slot")
			}
			count++
		} else if exact {
			return 0, errors.New("fixture tuple exists at another RPDB priority")
		}
	}
	return count, ctx.Err()
}

func (l *nativeRouterHTTPSLease) assertAbsent(ctx context.Context) error {
	if l.added || l.unknown {
		return errors.New("router HTTPS fixture lease has no confirmed cleanup")
	}
	count, err := l.count(ctx)
	if err != nil || count != 0 {
		return errors.Join(errors.New("router HTTPS fixture lease absence is unconfirmed"), err)
	}
	return nil
}

func (l *nativeRouterHTTPSLease) remove(ctx context.Context) error {
	if !l.added || l.unknown {
		return l.assertAbsent(ctx)
	}
	if err := l.guard(ctx); err != nil {
		return err
	}
	count, err := l.count(ctx)
	if err != nil || count != 1 {
		l.unknown = true
		return errors.Join(errors.New("owned fixture tuple changed before cleanup"), err)
	}
	if err := l.guard(ctx); err != nil {
		return err
	}
	// The successful exact add is the sole grant. An uncertain delete is not
	// retried from a matching readback, even inside this owned namespace.
	l.unknown = true
	if _, err := l.command(ctx, l.mutation("delete")...); err != nil {
		return err
	}
	count, err = l.count(ctx)
	if err != nil || count != 0 {
		return errors.Join(errors.New("exact fixture deletion did not establish absence"), err)
	}
	l.added, l.unknown = false, false
	return nil
}

func (l *nativeRouterHTTPSLease) route(ctx context.Context) error {
	output, err := l.command(ctx, "-N", "-4", "route", "get", l.request.Destination.String(),
		"from", l.request.Source.String(), "oif", l.request.Interface)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 || fields[0] != l.request.Destination.String() {
		return errors.New("router HTTPS route destination is unconfirmed")
	}
	want := map[string]string{"from": l.request.Source.String(), "dev": l.request.Interface, "table": strconv.Itoa(l.table)}
	seen := map[string]bool{}
	for i, field := range fields {
		if field == "via" || field == "nexthop" || field == "error" {
			return errors.New("router HTTPS route does not lead directly to the owned TUN")
		}
		if value, ok := want[field]; ok {
			if seen[field] || i+1 >= len(fields) || fields[i+1] != value {
				return errors.New("router HTTPS route ownership is ambiguous")
			}
			seen[field] = true
		}
	}
	if len(seen) != len(want) {
		return errors.New("router HTTPS route misses its source, TUN or owned table")
	}
	return ctx.Err()
}

func nativeRouterHTTPSRPFilter(t *testing.T, device string) error {
	t.Helper()
	values := map[string]int{}
	for _, name := range []string{"all", "default", device} {
		data, err := os.ReadFile(filepath.Join("/proc/sys/net/ipv4/conf", name, "rp_filter"))
		if err != nil || len(data) > 16 {
			return errors.Join(errors.New("fixture reverse-path capability is unavailable"), err)
		}
		value, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || value < 0 || value > 2 {
			return errors.New("fixture reverse-path capability is invalid")
		}
		values[name] = value
	}
	t.Logf("router TUN actual rp_filter: all=%d default=%d %s=%d (read only)", values["all"], values["default"], device, values[device])
	if max(values["all"], values[device]) == 1 {
		return errors.New("native router HTTPS fixture has strict reverse-path filtering")
	}
	return nil
}

// Called only after the existing fixture's real Activate/Health/Commit. The
// positive path injects only its local CA; OS inventory, source, ifindex,
// checked SO_BINDTODEVICE, TCP, TLS and accepted body are all real.
func nativeScopedXrayRouterHTTPS(t *testing.T, ctx context.Context, a *ProxyTunnelAdapter, plan Plan, roots *x509.CertPool, expectedExit string) (lease *nativeRouterHTTPSLease, resultErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if os.Geteuid() != 0 || os.Getenv("RAZVILKA_XRAY_TUN_NATIVE") != "1" || os.Getenv("RAZVILKA_XRAY_TUN_ROLE") != "router" || os.Getenv("RAZVILKA_XRAY_ROUTER_HTTPS_NATIVE") != "1" || roots == nil {
		return nil, errors.New("router HTTPS component requires its explicit owned fixture role and CA")
	}
	root := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	if len(root) > 4096 || !filepath.IsAbs(root) || filepath.Clean(a.StateRoot) != filepath.Join(root, "router-state") {
		return nil, errors.New("router HTTPS component requires its absolute private fixture root")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.Join(errors.New("router HTTPS fixture root is not a private directory"), err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("router HTTPS fixture root is owned by another user")
	}
	namespace, err := nativeRouterHTTPSNamespace()
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(a.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return nil, errors.New("actual adapter TUN source is unavailable")
	}
	iface, err := net.InterfaceByName(a.Interface)
	if err != nil {
		return nil, err
	}
	request := nodeRouterHTTPSRequest{URL: "https://service.example/probe", Interface: iface.Name,
		IfIndex: iface.Index, Source: prefix.Addr(), Destination: netip.MustParseAddr(nativeXrayHTTPSIP)}
	service := nativeRouterHTTPSService(request.URL, expectedExit)
	request.ServiceID = service.ID
	request.Predicate, err = newProxyServicePredicate(service)
	if err != nil {
		return nil, err
	}
	identity, err := a.scopedRuntimeIdentity()
	if err != nil {
		return nil, err
	}
	lease = &nativeRouterHTTPSLease{ip: a.ip(), request: request, table: a.Table, namespace: namespace}
	lease.guard = func(ctx context.Context) error {
		if err := a.verifyScopedNodeInterface(ctx); err != nil {
			return err
		}
		if _, err := a.checkScopedNodeState(ctx, plan); err != nil {
			return err
		}
		state, exists, err := a.loadPolicy()
		if err != nil || !exists || state.Interface != request.Interface || state.Table != lease.table {
			return errors.Join(errors.New("owned policy table changed across router HTTPS"), err)
		}
		if err := a.verifyCommittedReceipt(ctx, state); err != nil {
			return err
		}
		current, err := a.scopedRuntimeIdentity()
		if err != nil || current != identity {
			return errors.Join(errors.New("owned runtime changed across router HTTPS"), err)
		}
		return nodeRouterAssignedSource(ctx, request, nodeRouterHTTPSOptions{})
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, lease.remove(cleanup))
	}()
	if err := lease.guard(ctx); err != nil {
		return lease, err
	}
	if err := nativeRouterHTTPSRPFilter(t, request.Interface); err != nil {
		return lease, err
	}
	count, err := lease.count(ctx)
	if err != nil || count != 0 {
		return lease, errors.Join(errors.New("router HTTPS fixture lease preexists"), err)
	}
	if err := lease.guard(ctx); err != nil {
		return lease, err
	}
	lease.unknown = true
	if _, err := lease.command(ctx, lease.mutation("add")...); err != nil {
		return lease, err
	}
	lease.added, lease.unknown = true, false
	count, err = lease.count(ctx)
	if err != nil || count != 1 {
		lease.unknown = true
		return lease, errors.Join(errors.New("exact router HTTPS fixture lease is unconfirmed"), err)
	}
	if err := lease.route(ctx); err != nil {
		return lease, err
	}
	if err := nativeRouterHTTPSNegativeGuards(ctx, request, roots); err != nil {
		return lease, err
	}
	falseService := nativeRouterHTTPSService(request.URL, expectedExit)
	falseService.Probes[0].Expect.BodyContains = append(falseService.Probes[0].Expect.BodyContains, "fixture-impossible-service-marker")
	falseRequest := request
	falseRequest.Predicate, err = newProxyServicePredicate(falseService)
	if err != nil {
		return lease, err
	}
	if err := lease.guard(ctx); err != nil {
		return lease, err
	}
	// The server still sends its real HTTP 200 over the same admitted TUN
	// source/destination. A stronger catalog predicate must reject that body.
	falseResult, falseErr := runNodeRouterHTTPSProbe(ctx, falseRequest, nodeRouterHTTPSOptions{roots: roots})
	var semanticErr *serviceResponseError
	if !errors.As(falseErr, &semanticErr) || falseResult.HTTPStatus != 200 || falseResult.ServiceAccepted || falseResult.BodySHA256 != "" ||
		falseResult.ServiceID != falseRequest.ServiceID || falseResult.ProbeID != falseService.Probes[0].ID ||
		falseResult.PredicateHash != falseRequest.Predicate.digest() || falseResult.BodyBytes != 0 {
		return lease, errors.New("controlled HTTP 200 bypassed the frozen service predicate")
	}
	if err := lease.guard(ctx); err != nil {
		return lease, err
	}
	result, err := runNodeRouterHTTPSProbe(ctx, request, nodeRouterHTTPSOptions{roots: roots})
	if err != nil {
		return lease, err
	}
	expected, err := json.Marshal(map[string]any{"ip": expectedExit, "accepted": true})
	if err != nil {
		return lease, err
	}
	expected = append(expected, '\n')
	digest := sha256.Sum256(expected)
	if !result.ServiceAccepted || result.Origin != nodeRouterHTTPSOrigin || result.Interface != request.Interface ||
		result.ServiceID != service.ID || result.ProbeID != service.Probes[0].ID || result.PredicateHash != request.Predicate.digest() ||
		result.IfIndex != request.IfIndex || result.Source.Addr() != request.Source || result.Source.Port() == 0 ||
		result.Destination != netip.AddrPortFrom(request.Destination, 443) || result.HTTPStatus != 200 ||
		result.BodySHA256 != hex.EncodeToString(digest[:]) || result.BodyBytes != len(expected) ||
		result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		return lease, errors.New("actual router TUN HTTPS did not prove its expected controlled exit/body")
	}
	if err := lease.guard(ctx); err != nil {
		return lease, err
	}
	if err := lease.remove(ctx); err != nil {
		return lease, err
	}
	t.Logf("actual router-origin TUN HTTPS accepted controlled exit %s, body SHA256=%s; exact temporary lease removed before lifecycle resumes", expectedExit, result.BodySHA256)
	return lease, nil
}

func nativeRouterHTTPSService(rawURL, expectedExit string) catalog.Service {
	return catalog.Service{ID: "native-site", Name: "Native site", Category: "native", Strategy: []string{"xray"},
		Domains: []string{"service.example"}, ProbeURL: rawURL, Probes: []catalog.Probe{{
			ID: "router-https", Label: "Router HTTPS", URL: rawURL, Required: true,
			Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectPolicy: "none",
				ContentTypes: []string{"application/json"}, JSON: true, JSONFields: []string{"accepted", "ip"},
				BodyContains: []string{`"accepted":true`, `"ip":"` + expectedExit + `"`}},
		}}}
}

func nativeRouterHTTPSNegativeGuards(ctx context.Context, request nodeRouterHTTPSRequest, roots *x509.CertPool) error {
	wrongIndex := request
	wrongIndex.IfIndex++
	unassigned := request
	unassigned.Source = request.Source.Next()
	for _, bad := range []nodeRouterHTTPSRequest{wrongIndex, unassigned} {
		result, err := runNodeRouterHTTPSProbe(ctx, bad, nodeRouterHTTPSOptions{roots: roots})
		if !errors.Is(err, errNodeRouterHTTPSUnavailable) || result.ServiceAccepted || result.BodySHA256 != "" {
			return errors.New("actual source/ifindex mismatch did not fail closed")
		}
	}
	bindCalls := 0
	result, err := runNodeRouterHTTPSProbe(ctx, request, nodeRouterHTTPSOptions{roots: roots,
		bind: func(syscall.RawConn, string) error {
			bindCalls++
			return errors.New("native fixture refuses device binding")
		}})
	if !errors.Is(err, errNodeRouterHTTPSUnavailable) || bindCalls != 1 || result.ServiceAccepted || result.BodySHA256 != "" {
		return fmt.Errorf("failed actual socket binding did not fail closed (calls=%d)", bindCalls)
	}
	return nil
}
