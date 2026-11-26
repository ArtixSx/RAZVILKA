package dnscontrol

import (
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"reflect"
	"testing"
)

func TestAnswerDetailsKeepsMinimumChainTTLAndZero(t *testing.T) {
	query, _ := buildDNSQueryFor(321, "service.example", dnsmessage.TypeA)
	var q dnsmessage.Message
	q.Unpack(query)
	for _, ttl := range []uint32{15, 0, 0x80000001} {
		reply := dnsmessage.Message{Header: dnsmessage.Header{ID: 321, Response: true, AuthenticData: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("alias.example.")}},
			{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("alias.example."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 25}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("target.example.")}},
			{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("target.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 40}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}},
		}}
		wire, _ := reply.Pack()
		got, err := dnsAnswerDetails(query, wire)
		want := ttl
		if ttl > 0x7fffffff {
			want = 0
		}
		if err != nil || got.TTLSeconds == nil || *got.TTLSeconds != want || !got.ResolverReportedAD || !reflect.DeepEqual(got.CNAMEChain, []string{"alias.example", "target.example"}) {
			t.Fatalf("lost details %+v %v", got, err)
		}
		reply.ID++
		wire, _ = reply.Pack()
		if _, err := dnsAnswerDetails(query, wire); !errors.Is(err, errDNSAnswer) {
			t.Fatal("invalid wire metadata accepted", err)
		}
	}
	nodata := dnsmessage.Message{Header: dnsmessage.Header{ID: 321, Response: true}, Questions: q.Questions}
	wire, _ := nodata.Pack()
	got, err := dnsAnswerDetails(query, wire)
	if !errors.Is(err, errDNSNoAddress) || got.TTLSeconds != nil {
		t.Fatal("negative cache lifetime invented", got, err)
	}
}
