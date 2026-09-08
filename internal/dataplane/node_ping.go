package dataplane

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// NodePingResult measures only TCP connect time. It grants no route authority
// and deliberately excludes endpoint addresses and raw network errors.
type NodePingResult struct {
	Reachable bool   `json:"reachable"`
	LatencyMS int64  `json:"latency_ms"`
	Message   string `json:"message"`
}

type NodePinger interface {
	Ping(context.Context, []byte) NodePingResult
}

type TCPNodePinger struct {
	resolve func(context.Context, string, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
}

func NewTCPNodePinger() *TCPNodePinger {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &TCPNodePinger{resolve: net.DefaultResolver.LookupNetIP, dial: dialer.DialContext}
}

func (p *TCPNodePinger) Ping(ctx context.Context, outbound []byte) NodePingResult {
	failed := NodePingResult{Message: "Сервер не ответил за 3 секунды."}
	if p == nil || p.resolve == nil || p.dial == nil || ctx.Err() != nil {
		return NodePingResult{Message: "Проверка отменена или недоступна."}
	}
	endpoint, err := inspectExactNodeOutbound(outbound)
	if err != nil {
		return NodePingResult{Message: "Адрес сервера не прошёл проверку."}
	}
	if endpoint.Protocol == "hysteria2" || endpoint.Protocol == "tuic" || endpoint.Transport == "quic" {
		return NodePingResult{Message: "Этот узел использует UDP. Выберите проверку сервиса."}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var addresses []netip.Addr
	if literal, parseErr := netip.ParseAddr(endpoint.Host); parseErr == nil {
		addresses = []netip.Addr{literal}
	} else {
		// Validate hostname syntax and special-use names before invoking DNS.
		if publicfetch.ValidateURL("https://"+endpoint.Host+"/") != nil {
			return NodePingResult{Message: "Адрес сервера не прошёл проверку."}
		}
		addresses, err = p.resolve(ctx, "ip", endpoint.Host)
		if err != nil {
			return NodePingResult{Message: "Не удалось определить адрес сервера."}
		}
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		return NodePingResult{Message: "Адрес сервера не прошёл проверку."}
	}
	for _, address := range addresses {
		if address.Is4In6() || !publicfetch.PublicAddress(address) {
			return NodePingResult{Message: "Адрес сервера не прошёл проверку."}
		}
	}
	// Each attempt uses an already validated literal; neither a second DNS
	// lookup nor a private-address fallback can occur after validation.
	for _, address := range addresses {
		if ctx.Err() != nil {
			return failed
		}
		started := time.Now()
		conn, dialErr := p.dial(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(endpoint.Port)))
		elapsed := time.Since(started).Milliseconds()
		if conn != nil {
			_ = conn.Close()
		}
		if dialErr == nil && conn != nil && ctx.Err() == nil {
			if elapsed < 1 {
				elapsed = 1
			}
			return NodePingResult{Reachable: true, LatencyMS: elapsed, Message: "TCP-соединение установлено. Работу сервиса проверьте отдельно."}
		}
	}
	return failed
}
