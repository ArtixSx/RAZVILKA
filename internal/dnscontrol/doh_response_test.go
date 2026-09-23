package dnscontrol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDoHHTTPAgeConsumesPositiveAndNegativeTTLWithoutRewritingDNS(t *testing.T) {
	for _, kind := range []string{"address", "alias", "nxdomain", "nodata", "negative-without-soa"} {
		for _, age := range []uint64{0, 20, 250, 600, 1 << 40} {
			t.Run(kind+"/"+strconv.FormatUint(age, 10), func(t *testing.T) {
				var original []byte
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					query, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					var q dnsmessage.Message
					if err := q.Unpack(query); err != nil {
						t.Error(err)
						return
					}
					message := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, AuthenticData: true}, Questions: q.Questions}
					if kind == "address" || kind == "alias" {
						owner := q.Questions[0].Name
						if kind == "alias" {
							owner = dnsmessage.MustNewName("target.example.")
							message.Answers = append(message.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: owner}})
						}
						message.Answers = append(message.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 600}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}})
					} else {
						if kind == "nxdomain" {
							message.RCode = dnsmessage.RCodeNameError
						}
						if kind != "negative-without-soa" {
							message.Authorities = []dnsmessage.Resource{negativeSOA("example.", 60, 30)}
						}
					}
					wire, err := message.Pack()
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Type", "application/dns-message")
					w.Header().Set("Age", strconv.FormatUint(age, 10))
					_, _ = w.Write(wire)
				}))
				defer server.Close()
				target := dnsTarget{endpoint: server.URL, detailedDoH: func(ctx context.Context, endpoint string, query []byte, _ bool) (dohResponse, error) {
					r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
					if err != nil {
						return dohResponse{}, err
					}
					response, err := server.Client().Do(r)
					if err != nil {
						return dohResponse{}, err
					}
					defer response.Body.Close()
					wire, err := io.ReadAll(response.Body)
					if err != nil {
						return dohResponse{}, err
					}
					original = append([]byte{}, wire...)
					response.Body = io.NopCloser(bytes.NewReader(wire))
					got, err := readDoHResponse(response)
					if !bytes.Equal(got.wire, original) {
						t.Error("HTTP cache processing rewrote signed DNS data")
					}
					return got, err
				}}
				got, err := exchangeCandidateDNSDetailed(context.Background(), target, "service.example", dnsmessage.TypeA)
				positive := kind == "address" || kind == "alias"
				if positive && err != nil || !positive && !errors.Is(err, errDNSNameError) && !errors.Is(err, errDNSNoAddress) {
					t.Fatal(got, err)
				}
				if !got.ResolverReportedAD {
					t.Fatal("resolver AD lost")
				}
				if kind == "negative-without-soa" {
					if got.NegativeTTLSeconds != nil || got.TTLSeconds != nil {
						t.Fatal("negative TTL invented", got)
					}
					return
				}
				lifetime := uint64(30)
				if kind == "address" {
					lifetime = 600
				}
				want := uint32(0)
				if age < lifetime {
					want = uint32(lifetime - age)
				}
				ttl := got.NegativeTTLSeconds
				if positive {
					ttl = got.TTLSeconds
				}
				if ttl == nil || *ttl != want {
					t.Fatalf("kind=%s age=%d got=%+v want=%d", kind, age, got, want)
				}
			})
		}
	}
}

func TestDoHRejectsInvalidHTTPMetadataAndOversizedBody(t *testing.T) {
	for _, test := range []struct {
		name        string
		contentType []string
		age         []string
		size        int
	}{
		{"absent-content-type", nil, nil, 12},
		{"html", []string{"text/html"}, nil, 12},
		{"duplicate-content-type", []string{"application/dns-message", "application/dns-message"}, nil, 12},
		{"negative-age", []string{"application/dns-message"}, []string{"-1"}, 12},
		{"plus-age", []string{"application/dns-message"}, []string{"+1"}, 12},
		{"empty-age", []string{"application/dns-message"}, []string{""}, 12},
		{"ambiguous-age", []string{"application/dns-message"}, []string{"1, 2"}, 12},
		{"duplicate-age", []string{"application/dns-message"}, []string{"1", "1"}, 12},
		{"overflow-age", []string{"application/dns-message"}, []string{"18446744073709551616"}, 12},
		{"decimal-age", []string{"application/dns-message"}, []string{"1.2"}, 12},
		{"oversize", []string{"application/dns-message"}, nil, 65536},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": test.contentType, "Age": test.age}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", test.size)))}
			defer response.Body.Close()
			if _, err := readDoHResponse(response); !errors.Is(err, errDNSAnswer) {
				t.Fatal("invalid response accepted", err)
			}
		})
	}
	for _, age := range []string{"0", "000250", " 250 ", "18446744073709551615"} {
		h := http.Header{"Content-Type": []string{"Application/DNS-Message"}, "Age": []string{age}}
		response := &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader("wire"))}
		if _, err := readDoHResponse(response); err != nil {
			t.Fatal("valid Age rejected", age, err)
		}
		response.Body.Close()
	}
	response := &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("unavailable"))}
	defer response.Body.Close()
	if _, err := readDoHResponse(response); serviceDNSErrorCode(err) != "DNS_HTTP_REJECTED" {
		t.Fatal(err)
	}
}
