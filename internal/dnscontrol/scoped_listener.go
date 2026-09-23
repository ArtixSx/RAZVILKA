package dnscontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Serve owns only the two explicitly bound sockets passed by the caller. It
// never binds wildcard/port 53, changes firewall/DHCP, or starts automatically.
// Cancellation closes listeners and connections, cancels DoH, and joins all
// workers before returning. A future dataplane owner must provide the separate
// transactional redirect/readback/rollback and a fresh epoch guard.
func (r *ScopedDNSResolver) Serve(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener) error {
	if udp == nil || tcp == nil {
		return ErrScopedDNS
	}
	u, uok := udp.LocalAddr().(*net.UDPAddr)
	t, tok := tcp.Addr().(*net.TCPAddr)
	if !uok || !tok || u.Port != t.Port || u.Port < 1024 || !u.IP.Equal(t.IP) || u.IP.IsUnspecified() || u.IP.IsMulticast() {
		return ErrScopedDNS
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer r.cache.clear()
	defer udp.Close()
	defer tcp.Close()
	var workers sync.WaitGroup
	var connections sync.Map
	slots := make(chan struct{}, 4)
	completed := make(chan error, 2)
	go func() {
		buffer := make([]byte, 4097)
		for {
			n, peer, err := udp.ReadFromUDPAddrPort(buffer)
			if err != nil {
				completed <- err
				return
			}
			if n > 4096 || !r.hasClient(peer.Addr().Unmap()) {
				continue
			}
			wire := append([]byte(nil), buffer[:n]...)
			select {
			case slots <- struct{}{}:
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer func() { <-slots }()
					reply := r.scopedReply(ctx, peer.Addr().Unmap(), wire, true)
					if ctx.Err() == nil && len(reply) > 0 {
						_, _ = udp.WriteToUDPAddrPort(reply, peer)
					}
				}()
			default:
				if reply := scopedDNSFailure(wire, dnsmessage.RCodeServerFailure, false); len(reply) > 0 {
					_, _ = udp.WriteToUDPAddrPort(reply, peer)
				}
			}
		}
	}()
	go func() {
		for {
			connection, err := tcp.AcceptTCP()
			if err != nil {
				completed <- err
				return
			}
			peer := connection.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
			if !r.hasClient(peer) {
				_ = connection.Close()
				continue
			}
			select {
			case slots <- struct{}{}:
				connections.Store(connection, struct{}{})
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer func() { <-slots }()
					defer connections.Delete(connection)
					defer connection.Close()
					// Multiple framed messages may share the connection. A bounded
					// session and idle deadline prevent an idle client taking a slot.
					for i := 0; i < 16 && ctx.Err() == nil; i++ {
						_ = connection.SetDeadline(time.Now().Add(6 * time.Second))
						var prefix [2]byte
						if _, err := io.ReadFull(connection, prefix[:]); err != nil {
							return
						}
						length := int(binary.BigEndian.Uint16(prefix[:]))
						if length < 12 || length > 4096 {
							return
						}
						wire := make([]byte, length)
						if _, err := io.ReadFull(connection, wire); err != nil {
							return
						}
						reply := r.scopedReply(ctx, peer, wire, false)
						if ctx.Err() != nil || len(reply) == 0 {
							return
						}
						binary.BigEndian.PutUint16(prefix[:], uint16(len(reply)))
						if _, err := io.Copy(connection, bytes.NewReader(append(prefix[:], reply...))); err != nil {
							return
						}
					}
				}()
			default:
				_ = connection.Close()
			}
		}
	}()
	var result error
	remaining := 2
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-completed:
		remaining--
	}
	cancel()
	_ = udp.Close()
	_ = tcp.Close()
	for ; remaining > 0; remaining-- {
		<-completed
	} // no new Add/connection after this barrier
	connections.Range(func(key, _ any) bool { _ = key.(*net.TCPConn).Close(); return true })
	workers.Wait()
	return result
}

func (r *ScopedDNSResolver) hasClient(client netip.Addr) bool {
	for key := range r.choices {
		if key.client == client {
			return true
		}
	}
	return false
}

func (r *ScopedDNSResolver) scopedReply(ctx context.Context, client netip.Addr, query []byte, udp bool) []byte {
	_, size, err := scopedDNSQuestion(query)
	if err != nil {
		return scopedDNSFailure(query, dnsmessage.RCodeRefused, false)
	}
	reply, err := r.Resolve(ctx, client, query)
	if err != nil {
		code := dnsmessage.RCodeServerFailure
		if errors.Is(err, ErrScopedDNS) {
			code = dnsmessage.RCodeRefused
		}
		return scopedDNSFailure(query, code, false)
	}
	if udp && len(reply) > size {
		return scopedDNSFailure(query, dnsmessage.RCodeSuccess, true)
	}
	return reply
}

func scopedDNSFailure(query []byte, code dnsmessage.RCode, truncated bool) []byte {
	var q dnsmessage.Message
	if len(query) > 4096 || q.Unpack(query) != nil || q.Response || len(q.Questions) != 1 {
		return nil
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true, CheckingDisabled: q.CheckingDisabled, RCode: code, Truncated: truncated}, Questions: q.Questions}
	wire, err := response.Pack()
	if err != nil {
		return nil
	}
	return wire
}
