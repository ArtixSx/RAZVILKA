package probecheck

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// NetworkTiming is request-local diagnostic data. No address, URL, certificate,
// error text or response bytes can enter this schema. Observed=false means no
// measurement, not a zero-cost phase. Durations overlap and must not be summed.
type NetworkPhase struct {
	Observed   bool   `json:"observed"`
	DurationUS int64  `json:"duration_us"`
	Status     string `json:"status,omitempty"`
}
type NetworkTiming struct {
	Status           string       `json:"status"`
	TLSAttempts      int          `json:"tls_attempts"`
	SOCKSAttempts    int          `json:"socks_attempts"`
	LaterRowsOmitted bool         `json:"later_rows_omitted,omitempty"`
	Sequence         int          `json:"sequence"`
	Kind             string       `json:"kind"`
	TotalUS          int64        `json:"total_us"`
	Headers          bool         `json:"headers_received"`
	Reused           bool         `json:"connection_reused"`
	DNS              NetworkPhase `json:"local_dns"`
	SOCKS            NetworkPhase `json:"socks_connect"`
	TLS              NetworkPhase `json:"tls"`
	TTFB             NetworkPhase `json:"ttfb"`
	Body             NetworkPhase `json:"body_read"`
	BodyBytes        int64        `json:"body_bytes"`
}
type networkTimingKey struct{}
type networkAttemptKey struct{}
type NetworkMeasurements struct {
	mu       sync.Mutex
	closed   bool
	rows     []*networkAttempt
	snapshot []NetworkTiming
}
type networkAttempt struct {
	owner                                  *NetworkMeasurements
	row                                    NetworkTiming
	start, tlsStart, bodyStart, socksStart time.Time
	done                                   bool
}

// WithNetworkMeasurements does not change a deadline, cancellation or verdict.
// Close freezes a bounded copy; callbacks arriving later cannot mutate it.
func WithNetworkMeasurements(ctx context.Context) (context.Context, *NetworkMeasurements) {
	m := &NetworkMeasurements{}
	return context.WithValue(ctx, networkTimingKey{}, m), m
}
func (m *NetworkMeasurements) begin(kind string) *networkAttempt {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	if len(m.rows) >= 32 {
		m.rows[len(m.rows)-1].row.LaterRowsOmitted = true
		return nil
	}
	a := &networkAttempt{owner: m, start: time.Now(), row: NetworkTiming{Sequence: len(m.rows) + 1, Kind: kind, Status: "incomplete"}}
	m.rows = append(m.rows, a)
	return a
}
func (a *networkAttempt) update(f func(*networkAttempt)) {
	if a == nil {
		return
	}
	a.owner.mu.Lock()
	defer a.owner.mu.Unlock()
	if !a.owner.closed && !a.done {
		f(a)
	}
}
func networkPhase(start time.Time, err error) NetworkPhase {
	if start.IsZero() {
		return NetworkPhase{}
	}
	status := "complete"
	if err != nil {
		status = "failed"
	}
	return NetworkPhase{Observed: true, DurationUS: max(time.Since(start).Microseconds(), 0), Status: status}
}
func (m *NetworkMeasurements) Close() []NetworkTiming {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		for _, a := range m.rows {
			if !a.tlsStart.IsZero() && !a.row.TLS.Observed {
				a.row.TLS = networkPhase(a.tlsStart, nil)
				a.row.TLS.Status = "incomplete"
			}
			if !a.socksStart.IsZero() && !a.row.SOCKS.Observed {
				a.row.SOCKS = networkPhase(a.socksStart, nil)
				a.row.SOCKS.Status = "incomplete"
			}
			if !a.done {
				a.row.TotalUS = max(time.Since(a.start).Microseconds(), 0)
				if !a.bodyStart.IsZero() && !a.row.Body.Observed {
					a.row.Body = networkPhase(a.bodyStart, nil)
					a.row.Body.Status = "incomplete"
				}
				if !a.tlsStart.IsZero() && !a.row.TLS.Observed {
					a.row.TLS = networkPhase(a.tlsStart, nil)
					a.row.TLS.Status = "incomplete"
				}
			}
			m.snapshot = append(m.snapshot, a.row)
		}
	}
	return append([]NetworkTiming(nil), m.snapshot...)
}

// BeginLocalServiceDNS measures only the actual local resolver invocation.
// It does not claim that opaque proxy-side DNS was observed.
func BeginLocalServiceDNS(ctx context.Context) func(error) {
	m, _ := ctx.Value(networkTimingKey{}).(*NetworkMeasurements)
	a := m.begin("service-resolver")
	if a == nil {
		return func(error) {}
	}
	return func(err error) {
		a.update(func(a *networkAttempt) {
			a.row.DNS = networkPhase(a.start, err)
			a.row.Status = a.row.DNS.Status
			a.row.TotalUS = a.row.DNS.DurationUS
			a.done = true
		})
	}
}

// BeginSOCKSConnect measures the complete SOCKS dial, including the local proxy
// connection and negotiation. It is NOT a remote TCP handshake measurement.
func BeginSOCKSConnect(ctx context.Context) func(error) {
	a, _ := ctx.Value(networkAttemptKey{}).(*networkAttempt)
	if a == nil {
		return func(error) {}
	}
	start := time.Now()
	a.update(func(a *networkAttempt) {
		a.row.SOCKSAttempts++
		a.socksStart = start
		if a.row.SOCKSAttempts > 1 {
			a.row.SOCKS = NetworkPhase{Observed: true, Status: "multiple"}
		}
	})
	return func(err error) {
		a.update(func(a *networkAttempt) {
			if a.row.SOCKSAttempts == 1 {
				a.row.SOCKS = networkPhase(start, err)
			} else {
				a.row.SOCKS = NetworkPhase{Observed: true, Status: "multiple"}
			}
		})
	}
}

// TimingClient preserves the caller's transport, redirect policy and limits.
// Every RoundTrip, including a redirect, has its own isolated trace/body row.
func TimingClient(ctx context.Context, client *http.Client) *http.Client {
	m, _ := ctx.Value(networkTimingKey{}).(*NetworkMeasurements)
	if m == nil {
		return client
	}
	clone := *client
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	clone.Transport = networkTimingTransport{next: next, owner: m}
	return &clone
}

type networkTimingTransport struct {
	next  http.RoundTripper
	owner *NetworkMeasurements
}

func (t networkTimingTransport) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
func (t networkTimingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	a := t.owner.begin("service-http")
	if a == nil {
		return t.next.RoundTrip(request)
	}
	trace := &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) {
			a.update(func(a *networkAttempt) { a.row.Reused = a.row.Reused || i.Reused })
		},
		TLSHandshakeStart: func() {
			a.update(func(a *networkAttempt) {
				a.row.TLSAttempts++
				a.tlsStart = time.Now()
				if a.row.TLSAttempts > 1 {
					a.row.TLS = NetworkPhase{Observed: true, Status: "multiple"}
				}
			})
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			a.update(func(a *networkAttempt) {
				if a.row.TLSAttempts == 1 {
					a.row.TLS = networkPhase(a.tlsStart, err)
				} else {
					a.row.TLS = NetworkPhase{Observed: true, Status: "multiple"}
				}
			})
		},
		GotFirstResponseByte: func() {
			a.update(func(a *networkAttempt) {
				if !a.row.TTFB.Observed {
					a.row.TTFB = networkPhase(a.start, nil)
				}
			})
		},
	}
	ctx := context.WithValue(request.Context(), networkAttemptKey{}, a)
	ctx = httptrace.WithClientTrace(ctx, trace) // Composes, rather than replaces, existing hooks.
	response, err := t.next.RoundTrip(request.WithContext(ctx))
	a.update(func(a *networkAttempt) {
		a.row.Headers = response != nil && err == nil
		if err != nil {
			a.row.Status = "failed"
		}
		if err != nil || response == nil || response.Body == nil {
			a.row.TotalUS = max(time.Since(a.start).Microseconds(), 0)
			a.done = true
		}
	})
	if response != nil && response.Body != nil && err == nil {
		response.Body = &networkTimingBody{ReadCloser: response.Body, attempt: a}
	}
	return response, err
}

type networkTimingBody struct {
	io.ReadCloser
	attempt *networkAttempt
}

func (b *networkTimingBody) Read(p []byte) (int, error) {
	b.attempt.update(func(a *networkAttempt) {
		if a.bodyStart.IsZero() {
			a.bodyStart = time.Now()
		}
	})
	n, err := b.ReadCloser.Read(p)
	b.attempt.update(func(a *networkAttempt) {
		a.row.BodyBytes = min(a.row.BodyBytes+int64(n), 1<<30)
		if err != nil {
			observedErr := err
			if err == io.EOF {
				observedErr = nil
			}
			a.row.Body = networkPhase(a.bodyStart, observedErr)
		}
	})
	return n, err
}
func (b *networkTimingBody) Close() error {
	err := b.ReadCloser.Close()
	b.attempt.update(func(a *networkAttempt) {
		if !a.row.Body.Observed && !a.bodyStart.IsZero() {
			a.row.Body = networkPhase(a.bodyStart, err)
			if err == nil {
				a.row.Body.Status = "incomplete"
			}
		}
		if err != nil && a.row.Body.Observed {
			a.row.Body.Status = "failed"
		}
		a.row.TotalUS = max(time.Since(a.start).Microseconds(), 0)
		a.row.Status = a.row.Body.Status
		if a.row.Status == "" {
			a.row.Status = "incomplete"
		}
		a.done = true
	})
	return err
}
