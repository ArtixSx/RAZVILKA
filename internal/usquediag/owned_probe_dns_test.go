package usquediag

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Packet fixtures and fake CONNECT callbacks only: no resolver, listener,
// network socket, native binary, or live /proc observation is used here.
func ownedDNSFixtureQuery(t *testing.T, kind dnsmessage.Type) []byte {
	t.Helper()
	query, err := ownedDNSQuery("example.com", kind)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func ownedDNSFixtureResponse(t *testing.T, query []byte) dnsmessage.Message {
	t.Helper()
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil {
		t.Fatal(err)
	}
	return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}, Questions: q.Questions}
}

func ownedDNSFixturePack(t *testing.T, message dnsmessage.Message) []byte {
	t.Helper()
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func ownedDNSFixtureAddress(owner, raw string) dnsmessage.Resource {
	address := netip.MustParseAddr(raw)
	resource := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Class: dnsmessage.ClassINET, TTL: 30}}
	if address.Is4() {
		resource.Header.Type = dnsmessage.TypeA
		resource.Body = &dnsmessage.AResource{A: address.As4()}
	} else {
		resource.Header.Type = dnsmessage.TypeAAAA
		resource.Body = &dnsmessage.AAAAResource{AAAA: address.As16()}
	}
	return resource
}

func ownedDNSFixtureAlias(owner, target string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}}
}

func ownedDNSFixtureAnswer(t *testing.T, query []byte, address string) []byte {
	t.Helper()
	response := ownedDNSFixtureResponse(t, query)
	if address != "" {
		response.Answers = []dnsmessage.Resource{ownedDNSFixtureAddress(response.Questions[0].Name.String(), address)}
	}
	return ownedDNSFixturePack(t, response)
}

func TestOwnedDNSQueryPure(t *testing.T) {
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		query := ownedDNSFixtureQuery(t, kind)
		var message dnsmessage.Message
		if err := message.Unpack(query); err != nil || message.Response || !message.RecursionDesired || len(message.Questions) != 1 || len(message.Answers)+len(message.Authorities)+len(message.Additionals) != 0 {
			t.Fatalf("invalid query shape: %#v, %v", message, err)
		}
		question := message.Questions[0]
		if question.Name.String() != "example.com." || question.Class != dnsmessage.ClassINET || question.Type != kind {
			t.Fatalf("wrong question: %#v", question)
		}
	}
	for _, host := range []string{"", "localhost", "127.0.0.1", "::1", "example.com:443", "bad..example.com", "example.com\x00evil", "example.com\r\n", strings.Repeat("a", 64) + ".com"} {
		t.Run(host, func(t *testing.T) {
			if query, err := ownedDNSQuery(host, dnsmessage.TypeA); err == nil || len(query) != 0 {
				t.Fatalf("invalid hostname accepted: %q (%x, %v)", host, query, err)
			}
		})
	}
	if query, err := ownedDNSQuery("example.com", dnsmessage.TypeTXT); err == nil || len(query) != 0 {
		t.Fatalf("unsupported query type accepted: %x, %v", query, err)
	}
}

func TestOwnedDNSAnswerPurePublicAndCNAME(t *testing.T) {
	for _, fixture := range []struct {
		name string
		kind dnsmessage.Type
		ip   string
	}{
		{"A", dnsmessage.TypeA, "1.1.1.1"},
		{"AAAA", dnsmessage.TypeAAAA, "2606:4700:4700::1111"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			query := ownedDNSFixtureQuery(t, fixture.kind)
			want := []netip.Addr{netip.MustParseAddr(fixture.ip)}
			got, err := parseOwnedDNSAnswer(query, ownedDNSFixtureAnswer(t, query, fixture.ip))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("public answer: got %v, %v; want %v", got, err, want)
			}
			response := ownedDNSFixtureResponse(t, query)
			response.Answers = []dnsmessage.Resource{ownedDNSFixtureAlias("example.com.", "edge.example.com."), ownedDNSFixtureAlias("edge.example.com.", "terminal.example.com."), ownedDNSFixtureAddress("terminal.example.com.", fixture.ip)}
			// DNS record order does not change the coherent in-packet alias chain.
			response.Answers[0], response.Answers[2] = response.Answers[2], response.Answers[0]
			got, err = parseOwnedDNSAnswer(query, ownedDNSFixturePack(t, response))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("coherent CNAME answer: got %v, %v; want %v", got, err, want)
			}
			got, err = parseOwnedDNSAnswer(query, ownedDNSFixtureAnswer(t, query, ""))
			if err != nil || len(got) != 0 {
				t.Fatalf("one-family NODATA must remain available to aggregate resolver: %v, %v", got, err)
			}
		})
	}
}

func TestOwnedDNSAnswerPureRejectsUnsafeOrUncorrelated(t *testing.T) {
	query := ownedDNSFixtureQuery(t, dnsmessage.TypeA)
	for name, mutate := range map[string]func(*dnsmessage.Message){
		"private only": func(m *dnsmessage.Message) { m.Answers[0] = ownedDNSFixtureAddress("example.com.", "10.0.0.1") },
		"mixed A": func(m *dnsmessage.Message) {
			m.Answers = append(m.Answers, ownedDNSFixtureAddress("example.com.", "192.168.1.1"))
		},
		"mixed A AAAA": func(m *dnsmessage.Message) {
			m.Answers = append(m.Answers, ownedDNSFixtureAddress("example.com.", "fd00::1"))
		},
		"loopback":    func(m *dnsmessage.Message) { m.Answers[0] = ownedDNSFixtureAddress("example.com.", "127.0.0.1") },
		"link local":  func(m *dnsmessage.Message) { m.Answers[0] = ownedDNSFixtureAddress("example.com.", "169.254.1.1") },
		"mapped IPv6": func(m *dnsmessage.Message) { m.Answers[0] = ownedDNSFixtureAddress("example.com.", "::ffff:1.1.1.1") },
		"private authority": func(m *dnsmessage.Message) {
			m.Authorities = []dnsmessage.Resource{ownedDNSFixtureAddress("ns.example.com.", "10.0.0.2")}
		},
		"private additional A": func(m *dnsmessage.Message) {
			m.Additionals = []dnsmessage.Resource{ownedDNSFixtureAddress("ns.example.com.", "172.16.0.1")}
		},
		"private additional AAAA": func(m *dnsmessage.Message) {
			m.Additionals = []dnsmessage.Resource{ownedDNSFixtureAddress("ns.example.com.", "fe80::1")}
		},
		"wrong id":             func(m *dnsmessage.Message) { m.ID++ },
		"not response":         func(m *dnsmessage.Message) { m.Response = false },
		"opcode":               func(m *dnsmessage.Message) { m.OpCode = 1 },
		"truncated":            func(m *dnsmessage.Message) { m.Truncated = true },
		"NXDOMAIN":             func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError },
		"SERVFAIL":             func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeServerFailure },
		"wrong question name":  func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.example.com.") },
		"wrong question type":  func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA },
		"wrong question class": func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS },
		"two questions":        func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
		"no question":          func(m *dnsmessage.Message) { m.Questions = nil },
		"wrong answer class":   func(m *dnsmessage.Message) { m.Answers[0].Header.Class = dnsmessage.ClassCHAOS },
		"alien terminal":       func(m *dnsmessage.Message) { m.Answers[0].Header.Name = dnsmessage.MustNewName("other.example.com.") },
		"CNAME cycle": func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{ownedDNSFixtureAlias("example.com.", "edge.example.com."), ownedDNSFixtureAlias("edge.example.com.", "example.com.")}
		},
		"conflicting CNAME": func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{ownedDNSFixtureAlias("example.com.", "edge.example.com."), ownedDNSFixtureAlias("example.com.", "other.example.com."), ownedDNSFixtureAddress("edge.example.com.", "1.1.1.1")}
		},
		"duplicate CNAME": func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{ownedDNSFixtureAlias("example.com.", "edge.example.com."), ownedDNSFixtureAlias("example.com.", "edge.example.com."), ownedDNSFixtureAddress("edge.example.com.", "1.1.1.1")}
		},
		"unused CNAME": func(m *dnsmessage.Message) {
			m.Answers = append(m.Answers, ownedDNSFixtureAlias("unrelated.example.com.", "edge.example.com."))
		},
		"address and CNAME same owner": func(m *dnsmessage.Message) {
			m.Answers = append(m.Answers, ownedDNSFixtureAlias("example.com.", "edge.example.com."), ownedDNSFixtureAddress("edge.example.com.", "1.0.0.1"))
		},
		"too many addresses": func(m *dnsmessage.Message) {
			for len(m.Answers) <= 32 {
				m.Answers = append(m.Answers, ownedDNSFixtureAddress("example.com.", "1.1.1.1"))
			}
		},
		"too long CNAME chain": func(m *dnsmessage.Message) {
			m.Answers = nil
			owner := "example.com."
			for i := 0; i < 9; i++ {
				next := strings.Repeat("a", i+1) + ".example.com."
				m.Answers = append(m.Answers, ownedDNSFixtureAlias(owner, next))
				owner = next
			}
			m.Answers = append(m.Answers, ownedDNSFixtureAddress(owner, "1.1.1.1"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := ownedDNSFixtureResponse(t, query)
			response.Answers = []dnsmessage.Resource{ownedDNSFixtureAddress("example.com.", "1.1.1.1")}
			mutate(&response)
			got, err := parseOwnedDNSAnswer(query, ownedDNSFixturePack(t, response))
			if !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
				t.Fatalf("unsafe answer accepted: %v, %v", got, err)
			}
		})
	}
	answer := ownedDNSFixtureAnswer(t, query, "1.1.1.1")
	for name, wire := range map[string][]byte{
		"empty":          nil,
		"short header":   answer[:11],
		"short resource": answer[:len(answer)-1],
		"trailing byte":  append(append([]byte(nil), answer...), 0),
		"body limit":     append(append([]byte(nil), answer...), make([]byte, ownedDoHBodyLimit)...),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseOwnedDNSAnswer(query, wire); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
				t.Fatalf("malformed wire accepted: %v, %v", got, err)
			}
		})
	}
	if got, err := parseOwnedDNSAnswer(nil, answer); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
		t.Fatalf("invalid query accepted: %v, %v", got, err)
	}
}

func TestOwnedDNSAnswerPureNODATAAndBoundaryFixtures(t *testing.T) {
	query := ownedDNSFixtureQuery(t, dnsmessage.TypeA)
	for name, answers := range map[string][]dnsmessage.Resource{
		"coherent CNAME NODATA":    {ownedDNSFixtureAlias("example.com.", "edge.example.com.")},
		"safe other-family NODATA": {ownedDNSFixtureAddress("example.com.", "2606:4700:4700::1111")},
	} {
		t.Run(name, func(t *testing.T) {
			response := ownedDNSFixtureResponse(t, query)
			response.Answers = answers
			if got, err := parseOwnedDNSAnswer(query, ownedDNSFixturePack(t, response)); err != nil || len(got) != 0 {
				t.Fatalf("safe NODATA: %v, %v", got, err)
			}
		})
	}
	response := ownedDNSFixtureResponse(t, query)
	owner := "example.com."
	for i := 0; i < 8; i++ {
		next := strings.Repeat("a", i+1) + ".example.com."
		response.Answers = append(response.Answers, ownedDNSFixtureAlias(owner, next))
		owner = next
	}
	response.Answers = append(response.Answers, ownedDNSFixtureAddress(owner, "1.1.1.1"))
	if got, err := parseOwnedDNSAnswer(query, ownedDNSFixturePack(t, response)); err != nil || !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("1.1.1.1")}) {
		t.Fatalf("eight-hop CNAME boundary: %v, %v", got, err)
	}
	response = ownedDNSFixtureResponse(t, query)
	for i := 0; i < 32; i++ {
		response.Answers = append(response.Answers, ownedDNSFixtureAddress("example.com.", "1.1.1.1"))
	}
	if got, err := parseOwnedDNSAnswer(query, ownedDNSFixturePack(t, response)); err != nil || len(got) != 1 {
		t.Fatalf("32 address RRs deduplicated after bounded validation: %v, %v", got, err)
	}
	response = ownedDNSFixtureResponse(t, query)
	response.Answers = []dnsmessage.Resource{ownedDNSFixtureAddress("example.com.", "1.1.1.1")}
	response.Additionals = []dnsmessage.Resource{ownedDNSFixtureAddress("ns.example.com.", "2606:4700:4700::1111")}
	if got, err := parseOwnedDNSAnswer(query, ownedDNSFixturePack(t, response)); err != nil || !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("1.1.1.1")}) {
		t.Fatalf("public additional is checked but not a CONNECT candidate: %v, %v", got, err)
	}
}

func TestOwnedDNSAnswerPureWireFramingAndEDNS(t *testing.T) {
	query := ownedDNSFixtureQuery(t, dnsmessage.TypeA)
	answer := ownedDNSFixtureAnswer(t, query, "1.1.1.1")
	for name, mutate := range map[string]func([]byte){
		"reserved Z flag":          func(wire []byte) { wire[3] |= 0x40 },
		"compression self pointer": func(wire []byte) { wire[12], wire[13] = 0xc0, 12 },
		"record count limit":       func(wire []byte) { binary.BigEndian.PutUint16(wire[6:8], 65) },
		"A short RDLENGTH":         func(wire []byte) { binary.BigEndian.PutUint16(wire[len(wire)-6:len(wire)-4], 3) },
		"A long RDLENGTH":          func(wire []byte) { binary.BigEndian.PutUint16(wire[len(wire)-6:len(wire)-4], 5) },
	} {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte(nil), answer...)
			mutate(wire)
			if got, err := parseOwnedDNSAnswer(query, wire); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
				t.Fatalf("invalid DNS framing: %v, %v", got, err)
			}
		})
	}
	for name, mutate := range map[string]func(*dnsmessage.Message){
		"extended RCODE":       func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL = 1 << 24 },
		"unknown EDNS version": func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL = 1 << 16 },
		"unknown EDNS flag":    func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL = 1 },
		"duplicate OPT":        func(m *dnsmessage.Message) { m.Additionals = append(m.Additionals, m.Additionals[0]) },
		"OPT in answers":       func(m *dnsmessage.Message) { m.Answers = append(m.Answers, m.Additionals[0]); m.Additionals = nil },
	} {
		t.Run(name, func(t *testing.T) {
			response := ownedDNSFixtureResponse(t, query)
			response.Answers = []dnsmessage.Resource{ownedDNSFixtureAddress("example.com.", "1.1.1.1")}
			response.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{}}}
			mutate(&response)
			if got, err := parseOwnedDNSAnswer(query, ownedDNSFixturePack(t, response)); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
				t.Fatalf("unsafe EDNS: %v, %v", got, err)
			}
		})
	}
	for _, count := range []int{64, 65} {
		response := ownedDNSFixtureResponse(t, query)
		response.Answers = []dnsmessage.Resource{ownedDNSFixtureAddress("example.com.", "1.1.1.1")}
		for len(response.Answers) < count {
			response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"x"}}})
		}
		wire := ownedDNSFixturePack(t, response)
		if len(wire) > 4096 {
			t.Fatal("record-budget fixture accidentally exceeds wire budget")
		}
		got, err := parseOwnedDNSAnswer(query, wire)
		if count == 64 {
			if err != nil || len(got) != 1 {
				t.Fatalf("64 RR boundary rejected: %v %v", got, err)
			}
		} else if !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
			t.Fatalf("complete 65 RR response accepted: %v %v", got, err)
		}
	}
	response := ownedDNSFixtureResponse(t, query)
	chunks := make([]string, 17)
	for i := range chunks {
		chunks[i] = strings.Repeat("x", 250)
	}
	response.Answers = []dnsmessage.Resource{ownedDNSFixtureAddress("example.com.", "1.1.1.1"), {Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: chunks}}}
	wire := ownedDNSFixturePack(t, response)
	if len(wire) <= 4096 {
		t.Fatal("wire-budget fixture accidentally remains within budget")
	}
	if got, err := parseOwnedDNSAnswer(query, wire); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
		t.Fatalf("complete oversized response accepted: %v %v", got, err)
	}
}

func TestOwnedResolvePublicPureFreshFamiliesAndBounds(t *testing.T) {
	for _, fixture := range []struct {
		name, a, aaaa string
		want          []netip.Addr
	}{
		{"both", "1.1.1.1", "2606:4700:4700::1111", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}},
		{"A NODATA", "", "2606:4700:4700::1111", []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}},
		{"AAAA NODATA", "1.1.1.1", "", []netip.Addr{netip.MustParseAddr("1.1.1.1")}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var calls []dnsmessage.Type
			exchange := func(ctx context.Context, query []byte) ([]byte, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 3*time.Second {
					t.Fatalf("exchange lacks bounded DNS deadline: %v, %v", deadline, ok)
				}
				message := ownedDNSFixtureResponse(t, query)
				kind := message.Questions[0].Type
				calls = append(calls, kind)
				ip := fixture.a
				if kind == dnsmessage.TypeAAAA {
					ip = fixture.aaaa
				}
				return ownedDNSFixtureAnswer(t, query, ip), nil
			}
			for attempt := 0; attempt < 2; attempt++ {
				got, err := ownedResolvePublic(context.Background(), "example.com", exchange)
				if err != nil || !reflect.DeepEqual(got, fixture.want) {
					t.Fatalf("resolve: %v, %v; want %v", got, err, fixture.want)
				}
			}
			wantCalls := []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeA, dnsmessage.TypeAAAA}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("cached, parallel, or incomplete resolution: %v", calls)
			}
		})
	}
}

func TestOwnedResolvePublicPureRefusesUnsafeAndCancellation(t *testing.T) {
	for _, fixture := range []struct {
		name, a, aaaa string
		wantCalls     int
	}{
		{"private A", "10.0.0.1", "2606:4700:4700::1111", 1},
		{"mixed A AAAA", "1.1.1.1", "fd00::1", 2},
		{"both NODATA", "", "", 2},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			calls := 0
			got, err := ownedResolvePublic(context.Background(), "example.com", func(_ context.Context, query []byte) ([]byte, error) {
				calls++
				ip := fixture.a
				if ownedDNSFixtureResponse(t, query).Questions[0].Type == dnsmessage.TypeAAAA {
					ip = fixture.aaaa
				}
				return ownedDNSFixtureAnswer(t, query, ip), nil
			})
			if !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 || calls != fixture.wantCalls {
				t.Fatalf("unsafe aggregate: %v, %v, calls %d", got, err, calls)
			}
		})
	}
	for _, during := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if !during {
			cancel()
		}
		calls := 0
		got, err := ownedResolvePublic(ctx, "example.com", func(_ context.Context, query []byte) ([]byte, error) {
			calls++
			cancel()
			return ownedDNSFixtureAnswer(t, query, "1.1.1.1"), nil
		})
		cancel()
		wantCalls := 0
		if during {
			wantCalls = 1
		}
		if !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 || calls != wantCalls {
			t.Fatalf("canceled resolve (during=%v): %v, %v, calls %d", during, got, err, calls)
		}
	}
	calls := 0
	if got, err := ownedResolvePublic(context.Background(), "localhost", func(context.Context, []byte) ([]byte, error) { calls++; return nil, nil }); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 || calls != 0 {
		t.Fatalf("invalid host exchanged: %v, %v, calls %d", got, err, calls)
	}
	if got, err := ownedResolvePublic(context.Background(), "example.com", nil); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
		t.Fatalf("nil exchange accepted: %v, %v", got, err)
	}
	if got, err := ownedResolvePublic(nil, "example.com", func(context.Context, []byte) ([]byte, error) {
		t.Fatal("nil context reached exchange")
		return nil, nil
	}); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
		t.Fatalf("nil context accepted: %v, %v", got, err)
	}
	for name, mode := range map[string]string{"exchange error": "error", "malformed exchange": "malformed", "aggregate RR limit": "limit", "CNAME-only aggregate NODATA": "nodata"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			got, err := ownedResolvePublic(context.Background(), "example.com", func(_ context.Context, query []byte) ([]byte, error) {
				calls++
				if mode == "error" {
					return nil, errors.New("private fixture diagnostic")
				}
				if mode == "malformed" {
					return []byte{1, 2, 3}, nil
				}
				response := ownedDNSFixtureResponse(t, query)
				if mode == "nodata" {
					response.Answers = []dnsmessage.Resource{ownedDNSFixtureAlias("example.com.", "edge.example.com.")}
				} else {
					ip := "1.1.1.1"
					if response.Questions[0].Type == dnsmessage.TypeAAAA {
						ip = "2606:4700:4700::1111"
					}
					for i := 0; i < 17; i++ {
						response.Answers = append(response.Answers, ownedDNSFixtureAddress("example.com.", ip))
					}
				}
				return ownedDNSFixturePack(t, response), nil
			})
			wantCalls := 1
			if mode == "limit" || mode == "nodata" {
				wantCalls = 2
			}
			if !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 || calls != wantCalls {
				t.Fatalf("unconfirmed aggregate: %v %v calls %d", got, err, calls)
			}
		})
	}
}

type ownedDNSFixtureRoundTripper func(*http.Request) (*http.Response, error)

func (f ownedDNSFixtureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type ownedDNSFixtureBody struct {
	io.Reader
	closed bool
}

func (b *ownedDNSFixtureBody) Close() error { b.closed = true; return nil }

func TestOwnedDoHExchangePureRequestAndResponseGuards(t *testing.T) {
	query := ownedDNSFixtureQuery(t, dnsmessage.TypeA)
	answer := ownedDNSFixtureAnswer(t, query, "1.1.1.1")
	for _, name := range []string{"valid", "status", "media type", "missing TLS", "unverified TLS", "oversized header", "oversized body", "canceled read"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			body := &ownedDNSFixtureBody{Reader: bytes.NewReader(answer)}
			client := &http.Client{Transport: ownedDNSFixtureRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				got, err := io.ReadAll(request.Body)
				if err != nil || !bytes.Equal(got, query) || request.Method != http.MethodPost || request.URL.String() != ownedDoHURL || request.Header.Get("Content-Type") != "application/dns-message" || request.Header.Get("Accept") != "application/dns-message" || request.Header.Get("Cache-Control") != "no-cache, no-store" || !request.Close {
					t.Fatalf("unexpected DoH request: %v %v", request, err)
				}
				response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/dns-message"}}, Body: body, ContentLength: int64(len(answer)), TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}, Request: request}
				switch name {
				case "status":
					response.StatusCode = http.StatusFound
				case "media type":
					response.Header.Set("Content-Type", "application/json")
				case "missing TLS":
					response.TLS = nil
				case "unverified TLS":
					response.TLS.VerifiedChains = nil
				case "oversized header":
					response.ContentLength = ownedDoHBodyLimit + 1
				case "oversized body":
					response.ContentLength = -1
					body.Reader = bytes.NewReader(make([]byte, ownedDoHBodyLimit+1))
				case "canceled read":
					cancel()
				}
				return response, nil
			})}
			got, err := ownedDoHExchange(ctx, client, query)
			if name == "valid" {
				if err != nil || !bytes.Equal(got, answer) {
					t.Fatalf("valid DoH: %x %v", got, err)
				}
			} else if !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 {
				t.Fatalf("unsafe DoH response: %x %v", got, err)
			}
			if calls != 1 || !body.closed {
				t.Fatalf("DoH lifecycle calls %d closed %v", calls, body.closed)
			}
		})
	}
	calls := 0
	client := &http.Client{Transport: ownedDNSFixtureRoundTripper(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected I/O") })}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, fixture := range []struct {
		ctx   context.Context
		query []byte
	}{{nil, query}, {ctx, query}, {context.Background(), nil}, {context.Background(), make([]byte, ownedDoHBodyLimit+1)}} {
		if got, err := ownedDoHExchange(fixture.ctx, client, fixture.query); !errors.Is(err, errOwnedNetworkDNS) || len(got) != 0 || calls != 0 {
			t.Fatalf("invalid DoH preflight reached transport: %x %v calls %d", got, err, calls)
		}
	}
}

type ownedDNSFixtureConn struct{ closed bool }

func (*ownedDNSFixtureConn) Read([]byte) (int, error)       { return 0, io.EOF }
func (*ownedDNSFixtureConn) Write(data []byte) (int, error) { return len(data), nil }
func (c *ownedDNSFixtureConn) Close() error                 { c.closed = true; return nil }
func (*ownedDNSFixtureConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (*ownedDNSFixtureConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18081}
}
func (*ownedDNSFixtureConn) SetDeadline(time.Time) error      { return nil }
func (*ownedDNSFixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (*ownedDNSFixtureConn) SetWriteDeadline(time.Time) error { return nil }

func TestOwnedDialPublicPurePinsLiteralAgainstRebinding(t *testing.T) {
	proxy := netip.MustParseAddrPort("127.0.0.1:18081")
	for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		t.Run(ip, func(t *testing.T) {
			resolved := []netip.Addr{netip.MustParseAddr(ip), netip.MustParseAddr("1.0.0.1")}
			resolveCalls, connectCalls := 0, 0
			sockets := &probeSockets{}
			fixture := &ownedDNSFixtureConn{}
			owner := newOwnedProbeTargetFixture(t, nil)
			connection, err := ownedDialPublic(owner.ctx, proxy, "example.com:443", sockets,
				func(_ context.Context, host string) ([]netip.Addr, error) {
					resolveCalls++
					if host != "example.com" {
						t.Fatalf("resolver hostname changed: %q", host)
					}
					if resolveCalls > 1 {
						return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
					}
					return resolved, nil
				},
				func(_ context.Context, gotProxy netip.AddrPort, command byte, address []byte, gotSockets *probeSockets) (net.Conn, []byte, error) {
					connectCalls++
					// Changing the original resolver result cannot move this CONNECT.
					resolved[0] = netip.MustParseAddr("10.0.0.1")
					want, _ := ownedSOCKSAddress(ip, 443)
					if gotProxy != proxy || command != 1 || gotSockets != sockets || !bytes.Equal(address, want) || address[0] == 3 {
						t.Fatalf("not fixed literal owned CONNECT: %v %d %x", gotProxy, command, address)
					}
					return fixture, nil, nil
				})
			if err != nil || connection != fixture || resolveCalls != 1 || connectCalls != 1 || fixture.closed {
				t.Fatalf("pinned dial: %v, %v, resolve %d connect %d closed %v", connection, err, resolveCalls, connectCalls, fixture.closed)
			}
			connection.Close()
		})
	}
}

func TestOwnedDialPublicPureRefusesWholeUnsafeSetBeforeCONNECT(t *testing.T) {
	proxy := netip.MustParseAddrPort("127.0.0.1:18081")
	tooMany := make([]netip.Addr, 33)
	for i := range tooMany {
		tooMany[i] = netip.MustParseAddr("1.1.1.1")
	}
	for _, fixture := range []struct {
		name       string
		addresses  []netip.Addr
		resolveErr error
	}{
		{"private only", []netip.Addr{netip.MustParseAddr("192.168.1.1")}, nil},
		{"mixed v4", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil},
		{"mixed families", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("fd00::1")}, nil},
		{"mapped", []netip.Addr{netip.MustParseAddr("::ffff:1.1.1.1")}, nil},
		{"zone", []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111%eth0")}, nil},
		{"invalid", []netip.Addr{{}}, nil},
		{"empty", nil, nil},
		{"error", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, errors.New("fixture private diagnostic")},
		{"limit", tooMany, nil},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			resolveCalls, connectCalls := 0, 0
			owner := newOwnedProbeTargetFixture(t, nil)
			connection, err := ownedDialPublic(owner.ctx, proxy, "example.com:443", &probeSockets{}, func(context.Context, string) ([]netip.Addr, error) {
				resolveCalls++
				return fixture.addresses, fixture.resolveErr
			}, func(context.Context, netip.AddrPort, byte, []byte, *probeSockets) (net.Conn, []byte, error) {
				connectCalls++
				return &ownedDNSFixtureConn{}, nil, nil
			})
			if !errors.Is(err, errOwnedNetworkDNS) || connection != nil || resolveCalls != 1 || connectCalls != 0 {
				t.Fatalf("unsafe set connected: %v %v resolve %d connect %d", connection, err, resolveCalls, connectCalls)
			}
		})
	}
}

func TestOwnedDialPublicPureCancellationLiteralAndNoFallback(t *testing.T) {
	proxy := netip.MustParseAddrPort("127.0.0.1:18081")
	for _, fixture := range []struct {
		name, target                                 string
		canceled, duringResolve, duringConnect, fail bool
		wantResolve, wantConnect                     int
	}{
		{"canceled", "example.com:443", true, false, false, false, 0, 0},
		{"cancel resolving", "example.com:443", false, true, false, false, 1, 0},
		{"cancel connecting", "example.com:443", false, false, true, false, 1, 1},
		{"connect error no fallback", "example.com:443", false, false, false, true, 1, 1},
		{"literal bypasses DNS", "1.1.1.1:443", false, false, false, false, 0, 1},
		{"IPv6 literal bypasses DNS", "[2606:4700:4700::1111]:443", false, false, false, false, 0, 1},
		{"private literal", "10.0.0.1:443", false, false, false, false, 0, 0},
		{"wrong port", "example.com:80", false, false, false, false, 0, 0},
		{"noncanonical port", "example.com:0443", false, false, false, false, 0, 0},
		{"localhost", "localhost:443", false, false, false, false, 0, 0},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			owner := newOwnedProbeTargetFixture(t, nil)
			ctx, cancel := context.WithCancel(owner.ctx)
			defer cancel()
			if fixture.canceled {
				cancel()
			}
			resolveCalls, connectCalls := 0, 0
			fake := &ownedDNSFixtureConn{}
			connection, err := ownedDialPublic(ctx, proxy, fixture.target, &probeSockets{}, func(context.Context, string) ([]netip.Addr, error) {
				resolveCalls++
				if fixture.duringResolve {
					cancel()
				}
				return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}, nil
			}, func(context.Context, netip.AddrPort, byte, []byte, *probeSockets) (net.Conn, []byte, error) {
				connectCalls++
				if fixture.duringConnect {
					cancel()
				}
				if fixture.fail {
					return fake, nil, errors.New("fixture connect failed")
				}
				return fake, nil, nil
			})
			wantSuccess := fixture.name == "literal bypasses DNS" || fixture.name == "IPv6 literal bypasses DNS"
			if (err == nil) != wantSuccess || (connection != nil) != wantSuccess || resolveCalls != fixture.wantResolve || connectCalls != fixture.wantConnect {
				t.Fatalf("dial lifecycle: %v %v resolve %d connect %d", connection, err, resolveCalls, connectCalls)
			}
			if (fixture.duringConnect || fixture.fail) && !fake.closed {
				t.Fatal("failed/canceled returned connection not closed")
			}
			if connection != nil {
				connection.Close()
			}
		})
	}
}
