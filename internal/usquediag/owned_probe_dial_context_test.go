package usquediag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// These regressions only inspect context values and use fake RoundTrippers.
// Real Transport/SOCKS sockets are confined to the separate opt-in harness.
func TestOwnedOperationContextSurvivesDetachedDial(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request, release := ownedOperationRequestContext(parent, 20*time.Second)
	defer release()
	detached := context.WithoutCancel(request)
	if _, ok := detached.Deadline(); ok || detached.Done() != nil {
		t.Fatal("fixture did not remove transport deadline/cancellation")
	}
	operation, err := ownedOperationDialContext(detached)
	parentDeadline, _ := parent.Deadline()
	if err != nil {
		t.Fatal(err)
	}
	if deadline, ok := operation.Deadline(); !ok || deadline != parentDeadline {
		t.Fatal("actual request deadline was not recovered")
	}
	cancel()
	if detached.Err() != nil || !errors.Is(operation.Err(), context.Canceled) {
		t.Fatal("original operation cancellation was not retained")
	}
	if _, err := ownedOperationDialContext(detached); !errors.Is(err, errOwnedNetworkStopped) {
		t.Fatal("canceled original operation admitted")
	}
}

func TestOwnedOperationDialContextFailsClosed(t *testing.T) {
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	canceled, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	for name, dial := range map[string]context.Context{
		"nil":                nil,
		"missing":            context.Background(),
		"wrong type":         context.WithValue(context.Background(), ownedOperationContextKey{}, "inert marker"),
		"unbounded original": context.WithValue(context.Background(), ownedOperationContextKey{}, context.Background()),
		"expired original":   context.WithValue(context.Background(), ownedOperationContextKey{}, expired),
		"canceled original":  context.WithValue(context.Background(), ownedOperationContextKey{}, canceled),
	} {
		t.Run(name, func(t *testing.T) {
			if operation, err := ownedOperationDialContext(dial); operation != nil || !errors.Is(err, errOwnedNetworkStopped) {
				t.Fatalf("unbound dial admitted: %v %v", operation, err)
			}
		})
	}
}

type ownedContextRoundTripper func(*http.Request) (*http.Response, error)

func (f ownedContextRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOwnedRequestsBindActualOperationAndDNSDeadline(t *testing.T) {
	outer, cancel := ownedOperationRequestContext(context.Background(), 20*time.Second)
	defer cancel()
	for _, dns := range []bool{false, true} {
		name := "HTTPS"
		limit := 20 * time.Second
		if dns {
			name, limit = "DoH", 3*time.Second
		}
		t.Run(name, func(t *testing.T) {
			started := time.Now()
			calls := 0
			client := &http.Client{Transport: ownedContextRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				operation, err := ownedOperationDialContext(context.WithoutCancel(request.Context()))
				if err != nil {
					t.Fatal(err)
				}
				deadline, bounded := operation.Deadline()
				if !bounded || !deadline.After(started) || deadline.Sub(started) > limit+time.Millisecond*10 {
					t.Fatal("request did not carry its own bounded deadline")
				}
				if dns {
					outerOperation, _ := ownedOperationDialContext(outer)
					outerDeadline, _ := outerOperation.Deadline()
					if operation == outerOperation || !deadline.Before(outerDeadline) || request.URL.String() != ownedDoHURL {
						t.Fatal("DoH inherited outer transport window or changed TLS hostname")
					}
				} else if request.URL.String() != "https://example.com/proof" {
					t.Fatal("HTTPS target hostname changed")
				}
				media := "text/plain"
				if dns {
					media = "application/dns-message"
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{media}}, Body: io.NopCloser(strings.NewReader("fixture body")), TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}}, nil
			})}
			var err error
			if dns {
				_, err = ownedDoHExchange(outer, client, make([]byte, 12))
			} else {
				_, err = ownedHTTPSBody(outer, client, "https://example.com/proof", "", 256, true)
			}
			if err != nil || calls != 1 {
				t.Fatalf("request context fixture: calls %d, %v", calls, err)
			}
		})
	}
}
