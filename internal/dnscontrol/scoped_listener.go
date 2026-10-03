package dnscontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ScopedDNSHandler keeps client admission, DNS selection and publication under
// the same runtime owner. Publish must hold the current generation/device lease
// while invoking send; a check performed only before Resolve is insufficient.
// NoMatch/default composition belongs to Resolve, never to the listener.
type ScopedDNSHandler struct {
	Admit   func(context.Context, netip.Addr) error
	Resolve func(context.Context, netip.Addr, []byte) ([]byte, error)
	Publish func(context.Context, netip.Addr, []byte, func() error) error
}

func (r *ScopedDNSResolver) Serve(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener) error {
	if r == nil || r.guard == nil {
		return ErrScopedDNS
	}
	defer r.cache.clear()
	return ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
		Admit: func(ctx context.Context, client netip.Addr) error {
			if !r.hasClient(client) {
				return ErrScopedDNS
			}
			return r.guard(ctx)
		},
		Resolve: r.resolveScopedWire,
		Publish: func(ctx context.Context, client netip.Addr, query []byte, send func() error) error {
			if err := r.guard(ctx); err != nil {
				return err
			}
			if message, _, err := scopedDNSQuestion(query); err == nil {
				host := strings.ToLower(strings.TrimSuffix(message.Questions[0].Name.String(), "."))
				if choice, exists := r.choices[scopedDNSKey{client: client, host: host}]; exists {
					if err := r.check(ctx, choice); err != nil {
						return err
					}
				}
			}
			return send()
		},
	})
}

// ServeScopedDNS owns only the two explicitly bound sockets passed by the caller. It
// never binds wildcard/port 53, changes firewall/DHCP, or starts automatically.
// Cancellation closes listeners and connections, cancels DoH, and joins all
// workers before returning. A future dataplane owner must provide the separate
// transactional redirect/readback/rollback and a fresh epoch guard.
func ServeScopedDNS(ctx context.Context, udp *net.UDPConn, tcp *net.TCPListener, handler ScopedDNSHandler) error {
	if udp == nil || tcp == nil || handler.Admit == nil || handler.Resolve == nil || handler.Publish == nil {
		return ErrScopedDNS
	}
	u, uok := udp.LocalAddr().(*net.UDPAddr)
	t, tok := tcp.Addr().(*net.TCPAddr)
	if !uok || !tok || u.Port != t.Port || u.Port < 1024 || !u.IP.Equal(t.IP) || u.IP.IsUnspecified() || u.IP.IsMulticast() {
		return ErrScopedDNS
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
			if n > 4096 || handler.Admit(ctx, peer.Addr().Unmap()) != nil {
				continue
			}
			wire := append([]byte(nil), buffer[:n]...)
			select {
			case slots <- struct{}{}:
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer func() { <-slots }()
					reply := scopedDNSHandlerReply(ctx, peer.Addr().Unmap(), wire, true, handler.Resolve)
					if ctx.Err() == nil && len(reply) > 0 {
						_ = publishScopedDNS(ctx, handler, peer.Addr().Unmap(), wire, func() error {
							if err := ctx.Err(); err != nil {
								return err
							}
							_, err := udp.WriteToUDPAddrPort(reply, peer)
							return err
						})
					}
				}()
			default:
				if reply := scopedDNSFailure(wire, dnsmessage.RCodeServerFailure, false); len(reply) > 0 {
					_ = publishScopedDNS(ctx, handler, peer.Addr().Unmap(), wire, func() error {
						if err := ctx.Err(); err != nil {
							return err
						}
						_, err := udp.WriteToUDPAddrPort(reply, peer)
						return err
					})
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
			if handler.Admit(ctx, peer) != nil {
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
						if handler.Admit(ctx, peer) != nil {
							return
						}
						reply := scopedDNSHandlerReply(ctx, peer, wire, false, handler.Resolve)
						if ctx.Err() != nil || len(reply) == 0 {
							return
						}
						binary.BigEndian.PutUint16(prefix[:], uint16(len(reply)))
						if err := publishScopedDNS(ctx, handler, peer, wire, func() error {
							if err := ctx.Err(); err != nil {
								return err
							}
							_, err := io.Copy(connection, bytes.NewReader(append(prefix[:], reply...)))
							return err
						}); err != nil {
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

// The closure is a synchronous, single-use send capability. Keeping it after
// Publish returns cannot bypass a later generation/device revocation.
func publishScopedDNS(ctx context.Context, handler ScopedDNSHandler, client netip.Addr, query []byte, send func() error) error {
	var gate sync.Mutex
	active, used := true, false
	err := handler.Publish(ctx, client, query, func() error {
		gate.Lock()
		defer gate.Unlock()
		if !active || used {
			return ErrScopedDNS
		}
		used = true
		if err := ctx.Err(); err != nil {
			return err
		}
		return send()
	})
	gate.Lock()
	active = false
	gate.Unlock()
	return err
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
	return scopedDNSHandlerReply(ctx, client, query, udp, r.resolveScopedWire)
}

func (r *ScopedDNSResolver) resolveScopedWire(ctx context.Context, client netip.Addr, query []byte) ([]byte, error) {
	wire, _, err := r.resolveClient(ctx, client, query)
	return wire, err
}

func scopedDNSHandlerReply(ctx context.Context, client netip.Addr, query []byte, udp bool, resolve func(context.Context, netip.Addr, []byte) ([]byte, error)) []byte {
	// The owner validates service/default semantics. The listener also supports
	// the existing explicit local baseline's non-address questions.
	_, size, err := scopedBaselineQuestion(query)
	if err != nil {
		return scopedDNSFailure(query, dnsmessage.RCodeRefused, false)
	}
	reply, err := resolve(ctx, client, query)
	if err != nil {
		code := dnsmessage.RCodeServerFailure
		if errors.Is(err, ErrScopedDNS) {
			code = dnsmessage.RCodeRefused
		}
		return scopedDNSFailure(query, code, false)
	}
	if len(reply) < 12 || len(reply) > 65535 {
		return scopedDNSFailure(query, dnsmessage.RCodeServerFailure, false)
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
