package dnscontrol

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func negativeSOA(owner string, ttl, minimum uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example."), MBox: dnsmessage.MustNewName("hostmaster.example."), MinTTL: minimum}}
}

func TestNegativeDNSLifetimeAndAliasCoverage(t *testing.T) {
	for _, family := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		query, _ := buildDNSQueryFor(71, "service.example", family)
		var q dnsmessage.Message
		q.Unpack(query)
		for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError} {
			for _, test := range []struct {
				name   string
				mutate func(*dnsmessage.Message)
				want   *uint32
			}{
				{"soa-minimum", func(*dnsmessage.Message) {}, uint32Pointer(30)},
				{"soa-header", func(m *dnsmessage.Message) { m.Authorities[0].Header.TTL = 15 }, uint32Pointer(15)},
				{"zero", func(m *dnsmessage.Message) { m.Authorities[0].Header.TTL = 0 }, uint32Pointer(0)},
				{"high-bit-header", func(m *dnsmessage.Message) { m.Authorities[0].Header.TTL = 0x80000001 }, uint32Pointer(0)},
				{"high-bit-minimum", func(m *dnsmessage.Message) { m.Authorities[0].Body.(*dnsmessage.SOAResource).MinTTL = 0xffffffff }, uint32Pointer(0)},
				{"no-soa", func(m *dnsmessage.Message) { m.Authorities = nil }, nil},
				{"unrelated-zone", func(m *dnsmessage.Message) {
					m.Authorities = []dnsmessage.Resource{negativeSOA("other.example.", 60, 30)}
				}, nil},
				{"not-a-label-suffix", func(m *dnsmessage.Message) { m.Authorities = []dnsmessage.Resource{negativeSOA("ample.", 60, 30)} }, nil},
				{"wrong-class", func(m *dnsmessage.Message) { m.Authorities[0].Header.Class = dnsmessage.ClassCHAOS }, nil},
				{"two-zones", func(m *dnsmessage.Message) {
					m.Authorities = append(m.Authorities, negativeSOA("service.example.", 10, 5))
				}, nil},
				{"alias-ttl", func(m *dnsmessage.Message) {
					m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 7}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("target.example.")}}}
				}, uint32Pointer(7)},
				{"alias-outside-zone", func(m *dnsmessage.Message) {
					m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 7}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("target.other.")}}}
				}, nil},
			} {
				t.Run(family.String()+"/"+rcode.String()+"/"+test.name, func(t *testing.T) {
					m := dnsmessage.Message{Header: dnsmessage.Header{ID: 71, Response: true, AuthenticData: true, RCode: rcode}, Questions: q.Questions, Authorities: []dnsmessage.Resource{negativeSOA("example.", 60, 30)}}
					test.mutate(&m)
					wire, e := m.Pack()
					if e != nil {
						t.Fatal(e)
					}
					got, err := dnsAnswerDetails(query, wire)
					kind, wantErr := "nodata", errDNSNoAddress
					if rcode == dnsmessage.RCodeNameError {
						kind, wantErr = "nxdomain", errDNSNameError
					}
					if !errors.Is(err, wantErr) || got.NegativeKind != kind || !reflect.DeepEqual(got.NegativeTTLSeconds, test.want) || got.TTLSeconds != nil || len(got.Addresses) != 0 || !got.ResolverReportedAD {
						t.Fatalf("got %+v err=%v want=%v", got, err, test.want)
					}
					if len(m.Answers) > 0 && len(got.CNAMEChain) != 1 {
						t.Fatal("negative answer lost alias")
					}
				})
			}
		}
	}
}

func uint32Pointer(value uint32) *uint32 { return &value }

func TestNegativeDNSStillChecksIntegrity(t *testing.T) {
	query, _ := buildDNSQueryFor(71, "service.example", dnsmessage.TypeA)
	for _, test := range []string{"wrong-id", "wrong-question", "truncated", "address-with-nxdomain", "loop", "broken-authority", "wrong-error-question"} {
		t.Run(test, func(t *testing.T) {
			var q dnsmessage.Message
			q.Unpack(query)
			m := dnsmessage.Message{Header: dnsmessage.Header{ID: 71, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: q.Questions}
			switch test {
			case "wrong-id":
				m.ID++
			case "wrong-question":
				m.Questions[0].Name = dnsmessage.MustNewName("other.example.")
			case "wrong-error-question":
				m.RCode = dnsmessage.RCodeServerFailure
				m.Questions[0].Name = dnsmessage.MustNewName("other.example.")
			case "truncated":
				m.Truncated = true
			case "address-with-nxdomain":
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}}}
			case "loop":
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: q.Questions[0].Name}}}
			}
			wire, _ := m.Pack()
			if test == "broken-authority" {
				wire[9] = 1
			}
			got, err := dnsAnswerDetails(query, wire)
			if !errors.Is(err, errDNSAnswer) || got.NegativeTTLSeconds != nil || got.NegativeKind != "" {
				t.Fatalf("invalid negative reply accepted: %+v %v", got, err)
			}
		})
	}
}
