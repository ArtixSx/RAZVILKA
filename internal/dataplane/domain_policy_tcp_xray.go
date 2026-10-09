package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// A single reviewed node and numeric real target. This is frozen intent, never
// a process receipt or permission to resolve a service name into capture rules.
type DomainPolicyTCPXraySpec struct {
	Generation, NetworkProfile, ServiceID, NodeID, Name string
	RealIP                                              netip.Addr
}

func (s DomainPolicyTCPXraySpec) valid() bool {
	name, err := config.PolicyDomain(s.Name)
	return lanPolicyHash(s.Generation) && s.NetworkProfile != "" && s.ServiceID != "" && exactNodeIDPattern.MatchString(s.NodeID) && err == nil && name == s.Name && domainPolicyTCPPublicIPv4(s.RealIP)
}

// The registered original Manager owner inventories this EXISTING adapter's
// process/config before Start and supplies the retained revocable lifetime.
// CheckTCPProcess rechecks that same registration/source, not a supplied hash
// DTO. Implementations must synchronously join consume and retain cleanup
// failures in the common journal. This leaf creates no separate journal.
type DomainPolicyTCPXrayOwner interface {
	WithTCPProcess(context.Context, ProcessSpec, string, func(context.Context) error) error
	CheckTCPProcess(context.Context, ProcessSpec, string) error
}

type DomainPolicyTCPXray struct {
	a              *ProxyTunnelAdapter
	owner          DomainPolicyTCPXrayOwner
	spec           DomainPolicyTCPXraySpec
	process        ProcessSpec
	endpoint       proxyNodeEndpoint
	sourceSeal     string
	configHash     string
	identity       string
	launchIdentity string
	address        string
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closed         bool
	connections    map[*domainPolicyTCPXrayConn]struct{}
	dialers        sync.WaitGroup
}

// WithDomainPolicyTCPXray runs the actual existing Xray engine without a TUN
// sidecar. Only its private fixed SOCKS inbound can reach the one reviewed
// VLESS exit, for the pinned numeric target TCP80/443. No TUN evidence is used.
func (a *ProxyTunnelAdapter) WithDomainPolicyTCPXray(ctx context.Context, spec DomainPolicyTCPXraySpec, owner DomainPolicyTCPXrayOwner, consume func(context.Context, *DomainPolicyTCPXray) error) error {
	if ctx == nil || a == nil || a.ID() != "xray" || a.NodeRoutes == nil || a.FreshProfile == nil || a.Processes == nil || owner == nil || consume == nil || !spec.valid() || a.SOCKSPort < 1 || a.SOCKSPort > 65535 {
		return ErrDomainPolicyTCPConsumer
	}
	data, seal, endpoint, err := a.materializeDomainPolicyTCPXray(ctx, spec)
	if err != nil {
		return err
	}
	defer clear(data)
	process := a.engineProcess()
	hash := routeidentity.Hash(data)
	return domainPolicyTCPSynchronousScope(ctx, func(consume func(context.Context) error) error {
		return owner.WithTCPProcess(ctx, process, hash, consume)
	}, func(ownerCtx context.Context) (result error) {
		if ownerCtx == nil || ownerCtx.Err() != nil || ctx.Err() != nil {
			return ErrDomainPolicyTCPConsumer
		}
		if err := owner.CheckTCPProcess(ownerCtx, process, hash); err != nil {
			return err
		}
		// Never overwrite the generic/exact-node runtime while it is running.
		if a.Processes.Running(process) || a.Processes.Running(a.sidecarProcess()) {
			return ErrDomainPolicyTCPConsumer
		}
		// Running may return false for a foreign/malformed retained PID. Do
		// not let Start replace its file or erase that owner's launch receipt.
		// The common owner must settle the old registration first.
		for _, path := range []string{process.PIDPath, process.PIDPath + routeidentity.ReceiptSuffix, a.sidecarProcess().PIDPath} {
			if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
				return errors.Join(ErrDomainPolicyTCPConsumer, err)
			}
		}
		if err := os.MkdirAll(process.Dir, 0o700); err != nil {
			return err
		}
		files, err := ownedfs.Open(process.Dir)
		if err != nil {
			return err
		}
		defer files.Close()
		if err := files.WriteAtomic("engine.json", data, 0o600); err != nil {
			return err
		}
		runtimeCtx, cancel := context.WithCancel(ownerCtx)
		defer cancel()
		stopParent := context.AfterFunc(ctx, cancel)
		defer stopParent()
		if ctx.Err() != nil {
			cancel()
		}
		runtime := &DomainPolicyTCPXray{a: a, owner: owner, spec: spec, process: process, endpoint: endpoint, sourceSeal: seal, configHash: hash,
			address: net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort)), ctx: runtimeCtx, cancel: cancel, connections: make(map[*domainPolicyTCPXrayConn]struct{})}
		// Source/profile/original registration are checked again after writing
		// private material and immediately before the real process launch.
		if err := runtime.checkSource(runtimeCtx); err != nil {
			return err
		}
		if err := a.Processes.Start(runtimeCtx, process); err != nil {
			return err
		}
		defer func() {
			runtime.close()
			// Keep the original launch passport through Stop. A replacement or
			// unknown identity is retained as common-owner cleanup pending;
			// matching current args/PID alone cannot authorize signaling it.
			current, err := a.verifyNodeProcess(process, "")
			if err != nil || runtime.launchIdentity == "" || current != runtime.launchIdentity {
				result = errors.Join(result, ErrDomainPolicyTCPConsumer, err)
				return
			}
			// Cancellation revokes forwarding, but cannot erase cleanup work.
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ownerCtx), 6*time.Second)
			defer cleanupCancel()
			result = errors.Join(result, a.Processes.Stop(cleanupCtx, process))
		}()
		launchIdentity, err := a.verifyNodeProcess(process, "")
		if err != nil || launchIdentity == "" {
			return errors.Join(ErrDomainPolicyTCPConsumer, err)
		}
		runtime.launchIdentity = launchIdentity
		if err := a.waitForSOCKSProcess(runtimeCtx, process, runtime.address); err != nil {
			return err
		}
		identity, err := a.verifyNodeProcess(process, runtime.address)
		if err != nil || identity == "" {
			return errors.Join(ErrDomainPolicyTCPConsumer, err)
		}
		runtime.identity = identity
		if err := runtime.check(runtimeCtx); err != nil {
			return err
		}
		return consume(runtimeCtx, runtime)
	})
}

func domainPolicyTCPXrayRequests(s DomainPolicyTCPXraySpec) []NodeRouteRequest {
	// Never resolve s.Name. This materializer mode validates the reviewed node
	// for one finite target, then installs a fixed private inbound route.
	return []NodeRouteRequest{{ServiceID: s.ServiceID, NodeID: s.NodeID, Destinations: []string{netip.PrefixFrom(s.RealIP, 32).String()}}}
}

func (a *ProxyTunnelAdapter) domainPolicyTCPXrayMaterial(ctx context.Context, spec DomainPolicyTCPXraySpec) (NodeRouteMaterial, string, error) {
	if err := errors.Join(ctx.Err(), checkAddressRefreshAuthority(ctx)); err != nil {
		return NodeRouteMaterial{}, "", err
	}
	profile, err := a.FreshProfile(ctx)
	if err != nil || profile != spec.NetworkProfile {
		return NodeRouteMaterial{}, "", errors.Join(ErrNodeEndpointChanged, err)
	}
	requests := domainPolicyTCPXrayRequests(spec)
	material, err := a.NodeRoutes(ctx, cloneScopedNodeRequests(requests), spec.NetworkProfile, time.Now().UTC())
	if err != nil || material.EngineID != "xray" {
		return NodeRouteMaterial{}, "", errors.Join(ErrExactNodeUnavailable, err)
	}
	material, err = copyScopedNodeMaterial(material)
	if err != nil {
		return NodeRouteMaterial{}, "", err
	}
	if err := validateScopedXrayConfig(material.Config, requests, 0); err != nil {
		clear(material.Config)
		return NodeRouteMaterial{}, "", err
	}
	seal, err := scopedNodeMaterialSeal(material)
	if err != nil {
		clear(material.Config)
		return NodeRouteMaterial{}, "", err
	}
	return material, seal, nil
}

func (a *ProxyTunnelAdapter) materializeDomainPolicyTCPXray(ctx context.Context, spec DomainPolicyTCPXraySpec) ([]byte, string, proxyNodeEndpoint, error) {
	material, seal, err := a.domainPolicyTCPXrayMaterial(ctx, spec)
	if err != nil {
		return nil, "", proxyNodeEndpoint{}, err
	}
	defer clear(material.Config)
	if err := a.requireScopedXHTTPRuntime(ctx, material.Config); err != nil {
		return nil, "", proxyNodeEndpoint{}, err
	}
	var doc map[string]any
	_ = json.Unmarshal(material.Config, &doc) // validated exact two exits above
	exit := doc["outbounds"].([]any)[1].(map[string]any)
	server := exit["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	host := server["address"].(string)
	addresses, err := a.resolveNodeEndpoint(ctx, host)
	if err != nil {
		return nil, "", proxyNodeEndpoint{}, err
	}
	// Preserve the TLS authority before replacing a remote endpoint hostname.
	if stream, ok := exit["streamSettings"].(map[string]any); ok && stream["security"] == "tls" {
		if tls, ok := stream["tlsSettings"].(map[string]any); ok && (tls["serverName"] == nil || tls["serverName"] == "") {
			tls["serverName"] = host
		}
	}
	endpoint := proxyNodeEndpoint{Host: host, IP: addresses[0].String(), Tag: scopedNodeTag(spec.NodeID)}
	server["address"] = endpoint.IP
	doc["inbounds"] = []any{map[string]any{"tag": "rz-domain-tcp-in", "listen": "127.0.0.1", "port": a.SOCKSPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}
	doc["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": []any{
		map[string]any{"type": "field", "inboundTag": []string{"rz-domain-tcp-in"}, "network": "tcp", "ip": []string{netip.PrefixFrom(spec.RealIP, 32).String()}, "port": "80,443", "outboundTag": endpoint.Tag},
		map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "rz-node-block"},
	}}
	data, err := json.Marshal(doc)
	return data, seal, endpoint, err
}

func (x *DomainPolicyTCPXray) matches(spec DomainPolicyTCPXraySpec) bool {
	return x != nil && x.spec == spec
}

func (x *DomainPolicyTCPXray) checkSource(ctx context.Context) error {
	if err := errors.Join(ctx.Err(), x.ctx.Err(), x.owner.CheckTCPProcess(ctx, x.process, x.configHash)); err != nil {
		return err
	}
	data, err := readBoundedProxyConfig(x.process.MatchArg)
	if err != nil {
		return err
	}
	defer clear(data)
	if routeidentity.Hash(data) != x.configHash {
		return ErrDomainPolicyTCPConsumer
	}
	material, seal, err := x.a.domainPolicyTCPXrayMaterial(ctx, x.spec)
	if err != nil {
		return err
	}
	clear(material.Config)
	if seal != x.sourceSeal {
		return ErrNodeEndpointChanged
	}
	addresses, err := x.a.resolveNodeEndpoint(ctx, x.endpoint.Host)
	found := false
	for _, address := range addresses {
		found = found || address.String() == x.endpoint.IP
	}
	if err != nil || !found {
		return ErrNodeEndpointChanged
	}
	return errors.Join(ctx.Err(), x.ctx.Err())
}

func (x *DomainPolicyTCPXray) check(ctx context.Context) error {
	if err := x.checkSource(ctx); err != nil {
		return err
	}
	identity, err := x.a.verifyNodeProcess(x.process, x.address)
	if err != nil || identity == "" || identity != x.identity || !x.a.Processes.Running(x.process) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return errors.Join(ctx.Err(), x.ctx.Err())
}

func (x *DomainPolicyTCPXray) dial(ctx context.Context, flow DomainPolicyTCPFlow, decision DomainPolicyDecision) (net.Conn, error) {
	if flow.synthetic == nil || !flow.synthetic.matches(flow) || !flow.synthetic.acceptsDecision(decision) || !x.matches(flow.synthetic.spec) {
		return nil, ErrDomainPolicyTCPConsumer
	}
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return nil, ErrDomainPolicyTCPConsumer
	}
	x.dialers.Add(1)
	x.mu.Unlock()
	defer x.dialers.Done()
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRuntime := context.AfterFunc(x.ctx, cancel)
	defer stopRuntime()
	if x.ctx.Err() != nil {
		cancel()
	}
	if err := x.check(dialCtx); err != nil {
		return nil, err
	}
	target := netip.AddrPortFrom(x.spec.RealIP, flow.Destination.Port())
	conn, err := domainPolicyTCPNumericSOCKS(dialCtx, x.address, target)
	if err != nil {
		return nil, err
	}
	if err := x.check(dialCtx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	tracked := &domainPolicyTCPXrayConn{Conn: conn, runtime: x}
	x.mu.Lock()
	if x.closed || ctx.Err() != nil || x.ctx.Err() != nil {
		x.mu.Unlock()
		_ = conn.Close()
		return nil, ErrDomainPolicyTCPConsumer
	}
	x.connections[tracked] = struct{}{}
	x.mu.Unlock()
	return tracked, nil
}

// Keep the actual *net.TCPConn so relay can half-close upstream after replay.
// Generic SOCKS wrappers can hide CloseWrite and deadlock request/response
// protocols waiting for EOF. The private endpoint allows only noauth CONNECT,
// with ATYP=IPv4; no hostname, UDP association or alternate/direct fallback.
func domainPolicyTCPNumericSOCKS(ctx context.Context, endpoint string, target netip.AddrPort) (_ *net.TCPConn, result error) {
	if !domainPolicyTCPPublicIPv4(target.Addr()) || (target.Port() != 80 && target.Port() != 443) {
		return nil, ErrDomainPolicyTCPConsumer
	}
	base, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", endpoint)
	if err != nil {
		return nil, err
	}
	conn := base.(*net.TCPConn)
	defer func() {
		if result != nil {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var auth [2]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		return nil, err
	}
	if auth != [2]byte{5, 0} {
		return nil, ErrDomainPolicyTCPConsumer
	}
	ip := target.Addr().As4()
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(target.Port() >> 8), byte(target.Port())}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, ErrDomainPolicyTCPConsumer
	}
	length := 0
	switch reply[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		length = int(size[0])
		if length == 0 {
			return nil, ErrDomainPolicyTCPConsumer
		}
	default:
		return nil, ErrDomainPolicyTCPConsumer
	}
	if _, err := io.CopyN(io.Discard, conn, int64(length+2)); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return conn, nil
}

func (x *DomainPolicyTCPXray) close() {
	x.mu.Lock()
	x.closed = true
	x.cancel()
	connections := make([]*domainPolicyTCPXrayConn, 0, len(x.connections))
	for conn := range x.connections {
		connections = append(connections, conn)
	}
	x.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	x.dialers.Wait()
}

type domainPolicyTCPXrayConn struct {
	net.Conn
	runtime *DomainPolicyTCPXray
	once    sync.Once
	err     error
}

func (c *domainPolicyTCPXrayConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.runtime.mu.Lock()
		delete(c.runtime.connections, c)
		c.runtime.mu.Unlock()
	})
	return c.err
}

func (c *domainPolicyTCPXrayConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return ErrDomainPolicyTCPConsumer
}
