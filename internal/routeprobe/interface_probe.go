package routeprobe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/commandrun"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const interfaceProbeEvidence = "source-address-and-kernel-route:"

var errProbeInterfaceRoute = errors.New("Сетевой маршрут через выбранный интерфейс не подтверждён")

func (m *Manager) interfaceProbeClient(ip net.IP, device, suffix string) (*http.Client, string, bool, error) {
	source, ok := netip.AddrFromSlice(ip)
	if !ok || !source.Unmap().Is4() {
		return nil, "", false, errProbeInterfaceRoute
	}
	source = source.Unmap()
	iface, err := net.InterfaceByName(device)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, "", false, errProbeInterfaceRoute
	}
	command := findSystemBinary([]string{"ip", "/opt/sbin/ip", "/opt/bin/ip"})
	if command == "" {
		return nil, "", false, errProbeInterfaceRoute
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: -1, LocalAddr: &net.TCPAddr{IP: ip}}
	dialer.SetMultipathTCP(false)
	dialer.ControlContext = func(ctx context.Context, _, _ string, conn syscall.RawConn) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return bindProbeSocket(conn, iface.Name)
	}
	current := func(ctx context.Context, peer netip.Addr) error {
		return readInterfaceProbeRoute(ctx, command, *iface, source, peer)
	}
	dial := checkedInterfaceDial(source, current, dialer.DialContext)
	transport := interfaceProbeTransport{dial: safeDialNetwork(dial, "ip4", "tcp4")}
	return hardenedHTTPClient(transport, m.timeout()), interfaceProbeEvidence + iface.Name + suffix, true, nil
}

type interfaceProbeTransport struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (r interfaceProbeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// net/http can detach its dial context to reuse a prospective connection.
	// A probe must instead cancel and join all attempts with this request.
	ctx, cancel := context.WithCancel(request.Context())
	var mu sync.Mutex
	var active sync.WaitGroup
	closed := false
	transport := newProbeHTTPTransport(func(_ context.Context, network, target string) (net.Conn, error) {
		mu.Lock()
		if closed {
			mu.Unlock()
			return nil, context.Canceled
		}
		active.Add(1)
		mu.Unlock()
		defer active.Done()
		return r.dial(ctx, network, target)
	})
	response, err := transport.RoundTrip(request)
	mu.Lock()
	closed = true
	mu.Unlock()
	cancel()
	active.Wait()
	return response, err
}

func checkedInterfaceDial(source netip.Addr, current func(context.Context, netip.Addr) error, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		peer, err := netip.ParseAddrPort(target)
		if network != "tcp4" || err != nil || !peer.Addr().Is4() || peer.Port() == 0 || !publicfetch.PublicAddress(peer.Addr()) {
			return nil, errProbeInterfaceRoute
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := current(ctx, peer.Addr()); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dial(ctx, network, target)
		if err != nil {
			return nil, err
		}
		local, localOK := conn.LocalAddr().(*net.TCPAddr)
		remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
		if !localOK || !remoteOK || local.AddrPort().Addr().Unmap() != source ||
			remote.AddrPort().Addr().Unmap() != peer.Addr() || remote.Port != int(peer.Port()) {
			_ = conn.Close()
			return nil, errProbeInterfaceRoute
		}
		if err = current(ctx, peer.Addr()); err == nil {
			err = ctx.Err()
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

func readInterfaceProbeRoute(ctx context.Context, command string, expected net.Interface, source, destination netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	iface, err := net.InterfaceByName(expected.Name)
	if err != nil || iface.Index != expected.Index || iface.Flags&net.FlagUp == 0 {
		return errProbeInterfaceRoute
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return errProbeInterfaceRoute
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil && prefix.Addr() == source {
			raw, err := commandrun.Output(ctx, 2*time.Second, 4<<10, command, "-4", "route", "get", destination.String(), "from", source.String())
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil || !interfaceProbeRouteMatches(string(raw), expected.Name, source, destination) {
				return errProbeInterfaceRoute
			}
			return nil
		}
	}
	return errProbeInterfaceRoute
}

func interfaceProbeRouteMatches(output, device string, source, destination netip.Addr) bool {
	header, extra, _ := strings.Cut(strings.TrimSpace(output), "\n")
	if extra = strings.TrimSpace(extra); extra != "" {
		fields := strings.Fields(extra)
		if fields[0] != "cache" || strings.Contains(extra, "\n") {
			return false
		}
	}
	fields := strings.Fields(header)
	if len(fields) < 3 || fields[0] != destination.String() {
		return false
	}
	matched := false
	for i := 1; i < len(fields); i++ {
		switch fields[i] {
		case "dev":
			if matched || i+1 >= len(fields) || fields[i+1] != device {
				return false
			}
			matched = true
			i++
		case "from":
			if i+1 >= len(fields) || fields[i+1] != source.String() {
				return false
			}
			i++
		}
	}
	return matched
}
