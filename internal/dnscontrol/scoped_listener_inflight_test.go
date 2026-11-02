package dnscontrol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestScopedUDPInflightDropsOnlySamePeerAndWire(t *testing.T) {
	udp, tcp := scopedSockets(t, "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan int32, 8)
	firstRelease := make(chan struct{})
	var admissions, exchanges atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
			Admit: func(context.Context, netip.Addr) error { admissions.Add(1); return nil },
			Exchange: func(c context.Context, _ netip.Addr, _ []byte, _ func([]byte) error) error {
				n := exchanges.Add(1)
				entered <- n
				if n <= 4 {
					select {
					case <-firstRelease:
					case <-c.Done():
					}
				} else {
					<-c.Done()
				}
				return errors.New("no publication issued")
			},
		})
	}()
	client := func() net.Conn {
		c, err := net.Dial("udp", udp.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	one, two := client(), client()
	query := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	write := func(c net.Conn, q []byte) {
		if _, err := c.Write(q); err != nil {
			t.Fatal(err)
		}
	}
	wait := func() {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("original worker did not enter", ctx.Err())
		}
	}
	write(one, query)
	wait()
	for range 20 {
		write(one, query)
	}
	differentID := append([]byte(nil), query...)
	differentID[0] ^= 1
	write(one, differentID)
	differentQuestion := scopedQuery(t, "different.example.com", dnsmessage.TypeA)
	copy(differentQuestion[:2], query[:2])
	write(one, differentQuestion)
	write(two, query)
	for range 3 {
		wait()
	}
	if admissions.Load() != 4 || exchanges.Load() != 4 {
		t.Fatal("duplicate reused admission or consumed another worker", admissions.Load(), exchanges.Load())
	}
	close(firstRelease)
	// Wait for the original worker's deferred removal using real retransmits;
	// no retained result is served. The fresh exchange remains blocked below.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for fresh := false; !fresh; {
		select {
		case n := <-entered:
			if n != 5 {
				t.Fatal("unexpected worker", n)
			}
			fresh = true
		case <-ticker.C:
			write(one, query)
		case <-ctx.Done():
			t.Fatal("joined request remained suppressed", ctx.Err())
		}
	}
	if admissions.Load() != 5 {
		t.Fatal("fresh request skipped admission", admissions.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled listener did not join actual workers")
	}
}

func TestScopedUDPInflightRefusalAndErrorReleaseOriginalKey(t *testing.T) {
	for _, kind := range []string{"admission-refused", "exchange-error"} {
		t.Run(kind, func(t *testing.T) {
			udp, tcp := scopedSockets(t, "127.0.0.1:0")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var attempts atomic.Int32
			first := make(chan struct{})
			fresh := make(chan struct{}, 1)
			done := make(chan error, 1)
			go func() {
				done <- ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler{
					Admit: func(context.Context, netip.Addr) error {
						if kind == "admission-refused" && attempts.Add(1) == 1 {
							close(first)
							return errors.New("refused")
						}
						return nil
					},
					Exchange: func(c context.Context, _ netip.Addr, _ []byte, _ func([]byte) error) error {
						if kind == "exchange-error" && attempts.Add(1) == 1 {
							close(first)
							return errors.New("failed")
						}
						fresh <- struct{}{}
						<-c.Done()
						return c.Err()
					},
				})
			}()
			c, err := net.Dial("udp", udp.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
			if _, err := c.Write(q); err != nil {
				t.Fatal(err)
			}
			select {
			case <-first:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for waiting := true; waiting; {
				select {
				case <-fresh:
					waiting = false
				case <-ticker.C:
					if _, err := c.Write(q); err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("failed key not released", ctx.Err())
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("workers not joined")
			}
		})
	}
}
