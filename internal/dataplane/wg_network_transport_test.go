package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func wgNetworkUDPReply(t *testing.T, query []byte) dnsmessage.Message {
	t.Helper()
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		t.Fatal(err)
	}
	body := dnsmessage.ResourceBody(&dnsmessage.AResource{A: netip.MustParseAddr("104.16.123.96").As4()})
	if request.Questions[0].Type == dnsmessage.TypeAAAA {
		body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700::6810:7b60").As16()}
	}
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: request.ID, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: request.Questions,
		Answers:   []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: request.Questions[0].Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: body}},
	}
}

func TestWGNetworkUDPRequiresRealMatchedDatagram(t *testing.T) {
	for _, family := range []string{"10.66.0.2", "fd66::2"} {
		for _, mode := range []string{"valid", "wrong id", "wrong question", "truncated", "refused", "private answer", "wrong answer family"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				query, err := wgNetworkUDPQuestion(netip.MustParseAddr(family))
				if err != nil {
					t.Fatal(err)
				}
				server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(time.Second))
				answer := wgNetworkUDPReply(t, query)
				switch mode {
				case "wrong id":
					answer.ID++
				case "wrong question":
					answer.Questions = append([]dnsmessage.Question(nil), answer.Questions...)
					answer.Questions[0].Name = dnsmessage.MustNewName("foreign.example.")
				case "truncated":
					answer.Truncated = true
				case "refused":
					answer.RCode = dnsmessage.RCodeRefused
				case "private answer":
					if netip.MustParseAddr(family).Is4() {
						answer.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}}
					} else {
						answer.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("fd66::1").As16()}
					}
				case "wrong answer family":
					answer.Answers[0].Header.Type = dnsmessage.TypeTXT
					answer.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{"handshake is not UDP evidence"}}
				}
				wire, err := answer.Pack()
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					buffer := make([]byte, 4096)
					_, peer, err := server.ReadFromUDP(buffer)
					if err == nil {
						_, err = server.WriteToUDP(wire, peer)
					}
					done <- err
				}()
				client, err := net.Dial("udp4", server.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				err = exchangeWGNetworkUDP(context.Background(), client, query)
				if (err == nil) != (mode == "valid") {
					t.Fatal("unmatched UDP transport proof", err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestWGNetworkTransportHealthRequiresAllFamiliesAndClasses(t *testing.T) {
	for _, failing := range []string{"", "tcp4", "udp4", "tcp6", "udp6"} {
		t.Run("failure="+failing, func(t *testing.T) {
			a, _, plan, _ := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
			a.RuntimeConfigPath = filepath.Join(t.TempDir(), "rz-wg.conf")
			if err := writeAtomic(a.RuntimeConfigPath, []byte(testOwnWireGuardProfile("")), 0o600); err != nil {
				t.Fatal(err)
			}
			var calls []string
			failure := errors.New("selected class failed")
			run := func(kind string) error {
				calls = append(calls, kind)
				if kind == failing {
					return failure
				}
				return nil
			}
			ctx := context.WithValue(context.Background(), reviewGuardKey{}, func(context.Context) error { return nil })
			err := a.probeWGNetworkFamilies(ctx, plan.RoutePlanFor(a.ID()), "", []netip.Addr{netip.MustParseAddr("10.66.0.2"), netip.MustParseAddr("fd66::2")},
				func(_ context.Context, _ string, source string) error {
					family := "tcp4"
					if netip.MustParseAddr(source).Is6() {
						family = "tcp6"
					}
					return run(family)
				}, func(_ context.Context, source netip.Addr) error {
					family := "udp4"
					if source.Is6() {
						family = "udp6"
					}
					return run(family)
				})
			if failing == "" {
				if err != nil || strings.Join(calls, ",") != "tcp4,udp4,tcp6,udp6" {
					t.Fatal("incomplete classes claimed healthy", calls, err)
				}
			} else if !errors.Is(err, failure) {
				t.Fatal("failed selected transport claimed healthy", calls, err)
			}
		})
	}
}

func TestWGNetworkProfileRequiresIndependentUDPControlCoverage(t *testing.T) {
	profile := strings.Replace(testOwnWireGuardProfile(""), "0.0.0.0/0", "93.0.0.0/8", 1)
	if _, err := wgNetworkProfileSources(context.Background(), profile, []string{"93.0.0.0/8"}); err == nil {
		t.Fatal("CIDR coverage alone claimed UDP capability")
	}
	profile = strings.Replace(profile, "93.0.0.0/8", "93.0.0.0/8, 1.1.1.1/32", 1)
	if sources, err := wgNetworkProfileSources(context.Background(), profile, []string{"93.0.0.0/8"}); err != nil || len(sources) != 1 || !sources[0].Is4() {
		t.Fatal("explicit control coverage failed", sources, err)
	}
}

func TestWGNetworkUDPCancellationClosesPendingExchange(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	client, err := net.Dial("udp4", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	query, err := wgNetworkUDPQuestion(netip.MustParseAddr("10.66.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- exchangeWGNetworkUDP(ctx, client, query) }()
	buffer := make([]byte, 512)
	if _, _, err := server.ReadFromUDP(buffer); err != nil {
		t.Fatal("query not sent", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancel did not fence the exchange", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel left UDP waiting for its full deadline")
	}
}

func TestWGNetworkOwnedRuntimeIdentityNeverPermitsSecondInterface(t *testing.T) {
	public, err := wgRuntimePublicKey([]byte(testOwnWireGuardProfile("")))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, inventory string
		allowed         bool
	}{
		{"one owned interface", "rz-wg\t" + public + "\n", true},
		{"second interface", "rz-wg\t" + public + "\nforeign-wg\t" + public + "\n", false},
		{"foreign only", "foreign-wg\t" + public + "\n", false},
		{"duplicate owned name", "rz-wg\t" + public + "\nrz-wg\t" + public + "\n", false},
		{"malformed trailing inventory", "rz-wg\t" + public + "\nnot a public key\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wgCanaryPublicInventoryForProbe([]byte(tc.inventory), public, "rz-wg")
			if (err == nil) != tc.allowed {
				t.Fatal("owned probe identity inventory", err)
			}
		})
	}
	if _, err := wgCanaryPublicInventory([]byte("rz-wg\t"+public+"\n"), public); !errors.Is(err, ErrWGCanaryIdentityInUse) {
		t.Fatal("ordinary candidate inherited the owned-runtime exception", err)
	}
}
