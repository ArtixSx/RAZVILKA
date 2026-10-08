// telegram-soak observes a previously verified, already running VLESS SOCKS
// endpoint. It never loads a profile, starts an engine, or changes a route.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"golang.org/x/net/proxy"
)

const telegramHost = "telegram.org"
const maxBody = 256 << 10

type options struct {
	SOCKS          string
	Pin            netip.Addr
	Duration       time.Duration
	Interval       time.Duration
	ProbeTimeout   time.Duration
	ControlTimeout time.Duration
	MTProto        bool
}

func (o options) cycleBudget() time.Duration {
	if o.MTProto {
		return o.ProbeTimeout + qaMTBudget
	}
	return o.ProbeTimeout
}

func defaults() options {
	return options{Duration: time.Hour, Interval: 30 * time.Second, ProbeTimeout: 10 * time.Second, ControlTimeout: 2 * time.Second}
}

func (o options) validate() error {
	host, port, err := net.SplitHostPort(o.SOCKS)
	address, parseErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || !address.IsLoopback() || address.Zone() != "" || address.Is4In6() || portErr != nil || number < 1 || number > 65535 ||
		o.Duration <= 0 || o.Duration > time.Hour || o.Interval < time.Second || o.Interval > 5*time.Minute ||
		o.ProbeTimeout <= 0 || o.ProbeTimeout > 30*time.Second || o.Duration <= o.cycleBudget() || o.ControlTimeout <= 0 || o.ControlTimeout > 5*time.Second ||
		o.Pin.IsValid() && (!o.Pin.Is4() || !publicfetch.PublicAddress(o.Pin)) {
		return errors.New("invalid options")
	}
	return nil
}

type control struct {
	OK        bool    `json:"ok"`
	Code      string  `json:"code"`
	LatencyMS float64 `json:"latency_ms"`
}

type sample struct {
	Code      string
	Status    int
	LatencyMS float64
}

type latency struct {
	Count  int     `json:"count"`
	MinMS  float64 `json:"min_ms"`
	MeanMS float64 `json:"mean_ms"`
	P50MS  float64 `json:"p50_ms"`
	P95MS  float64 `json:"p95_ms"`
	MaxMS  float64 `json:"max_ms"`
}

func summarize(values []float64) latency {
	if len(values) == 0 {
		return latency{}
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	var sum float64
	for _, value := range ordered {
		sum += value
	}
	return latency{len(ordered), ordered[0], sum / float64(len(ordered)), ordered[(len(ordered)-1)/2], ordered[int(math.Ceil(float64(len(ordered))*0.95))-1], ordered[len(ordered)-1]}
}

type report struct {
	Schema                  int             `json:"schema"`
	Tool                    string          `json:"tool"`
	BuildRevision           string          `json:"build_revision,omitempty"`
	BuildModified           bool            `json:"build_modified"`
	Service                 string          `json:"service"`
	Endpoint                string          `json:"loopback_socks_endpoint"`
	TargetMode              string          `json:"target_mode"`
	StartedAt               time.Time       `json:"started_at"`
	SamplingStartedAt       *time.Time      `json:"sampling_started_at,omitempty"`
	FinishedAt              time.Time       `json:"finished_at"`
	SamplingDurationSeconds float64         `json:"requested_sampling_seconds"`
	SamplingElapsedSeconds  float64         `json:"sampling_elapsed_seconds"`
	ElapsedSeconds          float64         `json:"elapsed_seconds"`
	IntervalSeconds         float64         `json:"interval_seconds"`
	ProbeTimeoutSeconds     float64         `json:"probe_timeout_seconds"`
	ControlTimeoutSeconds   float64         `json:"control_timeout_seconds"`
	WindowCompleted         bool            `json:"window_completed"`
	Outcome                 string          `json:"outcome"`
	ExitCode                int             `json:"exit_code"`
	Initial                 control         `json:"initial_endpoint_control"`
	Final                   control         `json:"final_endpoint_control"`
	Attempts                int             `json:"https_attempts"`
	Accepted                int             `json:"https_accepted"`
	Failures                int             `json:"https_failures"`
	FailureCodes            map[string]int  `json:"failure_codes"`
	HTTPStatuses            map[int]int     `json:"http_statuses"`
	SkippedSlots            int             `json:"skipped_overrun_slots"`
	AllLatency              latency         `json:"all_attempts_latency"`
	AcceptedLatency         latency         `json:"accepted_latency"`
	MTProto                 string          `json:"mtproto"`
	Protocol                *protocolReport `json:"mtproto_unauth,omitempty"`
	Limits                  []string        `json:"limits"`
}

type protocolReport struct {
	DC            int            `json:"dc"`
	BudgetSeconds float64        `json:"request_budget_seconds"`
	Attempts      int            `json:"attempts"`
	Replies       int            `json:"nonce_matched_respq"`
	Failures      int            `json:"failures"`
	FailureCodes  map[string]int `json:"failure_codes"`
	Latency       latency        `json:"latency"`
	Scope         string         `json:"scope"`
}

// The control is only a no-auth SOCKS5 greeting at the configured address.
// It does not authenticate the listener or prove an unchanged process/node.
func endpointControl(parent context.Context, o options) control {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, o.ControlTimeout)
	defer cancel()
	r := control{Code: "connect_failed"}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", o.SOCKS)
	if err == nil {
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		_, err = conn.Write([]byte{5, 1, 0})
		var reply [2]byte
		if err == nil {
			_, err = io.ReadFull(conn, reply[:])
		}
		if err == nil && reply == [2]byte{5, 0} {
			r.OK, r.Code = true, "socks5_no_auth"
		} else {
			r.Code = "socks5_refused"
		}
	}
	if err != nil {
		r.Code = failureCode(ctx, err)
	}
	r.LatencyMS = float64(time.Since(started)) / float64(time.Millisecond)
	return r
}

type httpsProber struct {
	client    *http.Client
	transport *http.Transport
}

func newHTTPSProber(o options, roots *tls.Config) (*httpsProber, error) {
	dialer, err := proxy.SOCKS5("tcp", o.SOCKS, nil, &net.Dialer{})
	if err != nil {
		return nil, errors.New("SOCKS dialer unavailable")
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS cancellation unavailable")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: telegramHost}
	if roots != nil {
		if roots.InsecureSkipVerify {
			return nil, errors.New("TLS verification required")
		}
		config.RootCAs = roots.RootCAs // Local fixtures only; no CLI trust override.
	}
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != net.JoinHostPort(telegramHost, "443") || network != "tcp" {
				return nil, errors.New("target changed")
			}
			if o.Pin.IsValid() {
				target = net.JoinHostPort(o.Pin.String(), "443")
			}
			return contextDialer.DialContext(ctx, "tcp", target)
		},
	}
	return &httpsProber{transport: transport, client: &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func failureCode(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var netErr net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var certificateErr *tls.CertificateVerificationError
	if errors.As(err, &certificateErr) {
		return "tls_verification"
	}
	return "transport_failed"
}

func (p *httpsProber) probe(parent context.Context, timeout time.Duration) sample {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	r := sample{Code: "accepted"}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+telegramHost+"/", nil)
	request.Header.Set("User-Agent", "RAZVILKA-Telegram-Soak/1")
	response, err := p.client.Do(request)
	if err == nil {
		defer response.Body.Close()
		r.Status = response.StatusCode
		if r.Status < 200 || r.Status >= 300 {
			r.Code = "http_status"
		} else {
			var count int64
			count, err = io.CopyN(io.Discard, response.Body, maxBody+1)
			if err == io.EOF {
				err = nil
			}
			if count > maxBody {
				r.Code, err = "body_limit", nil
			}
		}
	}
	if err != nil {
		r.Code = failureCode(ctx, err)
	}
	if ctx.Err() != nil {
		r.Code = failureCode(ctx, ctx.Err())
	}
	r.LatencyMS = float64(time.Since(started)) / float64(time.Millisecond)
	return r
}

func contextStopCause(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Socket deadlines can fire before the context timer delivers Done/Err.
	if deadline, ok := ctx.Deadline(); ok && !now.Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func waitUntil(ctx context.Context, at time.Time) error {
	if err := contextStopCause(ctx, time.Now()); err != nil {
		return err
	}
	timer := time.NewTimer(max(0, time.Until(at)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	return contextStopCause(ctx, time.Now())
}

func observe(parent context.Context, o options, roots *tls.Config) (report, error) {
	if err := o.validate(); err != nil {
		return report{}, err
	}
	started := time.Now()
	r := report{Schema: 1, Tool: "telegram-soak/2", Service: "telegram_https", Endpoint: o.SOCKS, TargetMode: "hostname_over_socks",
		StartedAt: started.UTC(), SamplingDurationSeconds: o.Duration.Seconds(), IntervalSeconds: o.Interval.Seconds(), ProbeTimeoutSeconds: o.ProbeTimeout.Seconds(), ControlTimeoutSeconds: o.ControlTimeout.Seconds(),
		Outcome: "refused", ExitCode: 1, Final: control{Code: "not_attempted"}, FailureCodes: map[string]int{}, HTTPStatuses: map[int]int{},
		MTProto: "not_tested_not_requested",
		Limits:  []string{"HTTPS TLS validation, HTTP 2xx, <=64KiB headers and <=256KiB body only; redirects refused", "No authenticated chats, account login, media, voice or authenticated MTProto server identity; no auth-key creation", "Endpoint controls verify SOCKS5 greeting at one configured loopback address, not unchanged PID/config/VLESS node/WAN", "No LAN/TUN, application UI or release acceptance; the operator must separately verify VLESS runtime and network identity", "Sampling lasts the requested duration; initial and final controls add at most two control timeouts, excluding report output and scheduler delays"},
	}
	if o.MTProto {
		r.MTProto = "single_req_pq_multi_nonce_matched_resPQ_only"
		r.Protocol = &protocolReport{DC: 2, BudgetSeconds: qaMTBudget.Seconds(), FailureCodes: map[string]int{}, Scope: "One unauthenticated req_pq_multi/resPQ through the same configured SOCKS endpoint; nonce/framing/TL/time checks only, not server authentication, account, media or voice"}
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && len(setting.Value) == 40 {
				if _, err := hex.DecodeString(setting.Value); err == nil {
					r.BuildRevision = setting.Value
				}
			}
			if setting.Key == "vcs.modified" {
				r.BuildModified = setting.Value == "true"
			}
		}
	}
	if o.Pin.IsValid() {
		r.TargetMode = "fixed_public_ipv4_original_tls_host"
	}
	finalAttempted := false
	r.Initial = endpointControl(parent, o)
	if r.Initial.OK && contextStopCause(parent, time.Now()) == nil {
		prober, err := newHTTPSProber(o, roots)
		if err != nil {
			return report{}, err
		}
		defer prober.transport.CloseIdleConnections()
		samplingStarted := time.Now()
		at := samplingStarted.UTC()
		r.SamplingStartedAt = &at
		end := samplingStarted.Add(o.Duration)
		window, cancel := context.WithDeadline(parent, end)
		var all, accepted, protocolLatencies []float64
		for next := samplingStarted; next.Before(end); {
			if waitUntil(window, next) != nil {
				break
			}
			if time.Until(end) < o.cycleBudget() {
				break // Do not start a request without its full remaining budget.
			}
			observed := prober.probe(window, o.ProbeTimeout)
			r.Attempts++
			all = append(all, observed.LatencyMS)
			if observed.Status != 0 {
				r.HTTPStatuses[observed.Status]++
			}
			if observed.Code == "accepted" {
				r.Accepted++
				accepted = append(accepted, observed.LatencyMS)
			} else {
				r.Failures++
				r.FailureCodes[observed.Code]++
			}
			if o.MTProto {
				protocolStarted := time.Now()
				observation := qaMTProbe(window, o.SOCKS)
				r.Protocol.Attempts++
				protocolLatencies = append(protocolLatencies, float64(time.Since(protocolStarted))/float64(time.Millisecond))
				if observation.Reply {
					r.Protocol.Replies++
				} else {
					r.Protocol.Failures++
					r.Protocol.FailureCodes[observation.Code]++
				}
			}
			next = next.Add(o.Interval)
			for next.Before(time.Now()) && next.Before(end) {
				r.SkippedSlots++
				next = next.Add(o.Interval)
			}
		}
		_ = waitUntil(window, end)
		closedAt := time.Now()
		r.WindowCompleted = contextStopCause(parent, closedAt) == nil && !closedAt.Before(end)
		cancel()
		r.SamplingElapsedSeconds = time.Since(samplingStarted).Seconds()
		r.AllLatency, r.AcceptedLatency = summarize(all), summarize(accepted)
		if o.MTProto {
			r.Protocol.Latency = summarize(protocolLatencies)
		}
		if contextStopCause(parent, time.Now()) == nil {
			finalAttempted = true
			r.Final = endpointControl(parent, o)
			if r.WindowCompleted && r.Attempts > 0 {
				r.Outcome, r.ExitCode = "completed_with_failures", 2
				if r.Final.OK && r.Failures == 0 && (!o.MTProto || r.Protocol.Attempts == r.Attempts && r.Protocol.Replies == r.Protocol.Attempts) {
					r.Outcome, r.ExitCode = "completed", 0
				}
			}
		}
	}
	finished := time.Now()
	if cause := contextStopCause(parent, finished); cause != nil {
		if !finalAttempted {
			r.Final.Code = "not_attempted_parent_cancellation"
		}
		r.Outcome, r.ExitCode = "parent_deadline", 1
		if errors.Is(cause, context.Canceled) {
			r.Outcome, r.ExitCode = "canceled", 130
		}
	}
	r.FinishedAt, r.ElapsedSeconds = finished.UTC(), finished.Sub(started).Seconds()
	return r, nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `Build: go build -trimpath -o telegram-soak ./scripts/telegram-soak
Run on the same host as the previously verified running VLESS SOCKS listener:
  ./telegram-soak -socks 127.0.0.1:1080 -duration 1h -interval 30s > telegram-soak.json
Optional -mtproto adds one req_pq_multi/resPQ through that SOCKS to fixed production DC2 per cycle.
It checks unauthenticated echoed nonce and bounded wire format; no RSA/DH/server authentication or account methods.
Optional -telegram-ip PUBLIC_IPV4 uses a separately admitted literal with original TLS Host/SNI.
Defaults: probe-timeout 10s, control-timeout 2s; duration >0..1h, interval 1s..5m.
Duration must exceed probe-timeout (plus 3s with -mtproto); only cycles with that full remaining budget start.
No engine startup, credentials/profile reads, route changes, direct fallback, or local Telegram DNS.
TLS verification is mandatory; only https Telegram homepage 2xx with <=256KiB body is accepted.
SIGINT/SIGTERM cancel requests and waits; no final network control follows parent cancellation.
One bounded JSON summary is written at exit; no bodies, URLs, raw errors or credentials are emitted.
Exit 0: entire sampling window, both SOCKS controls, all HTTPS requests and all opted-in unauth resPQ checks accepted.
Exit 2: completed sampling with failed HTTPS/protocol requests or final endpoint control. Exit 1: refused/incomplete/deadline. Exit 130: canceled.
SOCKS controls do not prove unchanged process/node/config/WAN. Verify these separately before/after.
MTProto is not tested without -mtproto. Authenticated chats/media/voice, physical LAN/TUN and UI are not tested.
This prepares a read-only final test; Root owns the real hour, network gates and release.`)
}

func parseOptions(args []string) (options, bool, error) {
	o := defaults()
	fs := flag.NewFlagSet("telegram-soak", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Invalid values can contain private input; never echo them.
	var pin string
	fs.StringVar(&o.SOCKS, "socks", "", "literal loopback SOCKS endpoint")
	fs.StringVar(&pin, "telegram-ip", "", "optional separately admitted public IPv4")
	fs.BoolVar(&o.MTProto, "mtproto", false, "opt in to one unauthenticated req_pq_multi/resPQ per cycle")
	fs.DurationVar(&o.Duration, "duration", o.Duration, "sampling window")
	fs.DurationVar(&o.Interval, "interval", o.Interval, "scheduled request interval")
	fs.DurationVar(&o.ProbeTimeout, "probe-timeout", o.ProbeTimeout, "whole request timeout")
	fs.DurationVar(&o.ControlTimeout, "control-timeout", o.ControlTimeout, "SOCKS greeting timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return o, true, nil
		}
		return o, false, errors.New("invalid options")
	}
	if pin != "" {
		var err error
		o.Pin, err = netip.ParseAddr(pin)
		if err != nil {
			return o, false, errors.New("invalid options")
		}
	}
	if len(fs.Args()) != 0 {
		return o, false, errors.New("invalid options")
	}
	return o, false, o.validate()
}

func main() {
	o, help, err := parseOptions(os.Args[1:])
	if help {
		usage(os.Stdout)
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid options; use -help.")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	r, err := observe(ctx, o, nil)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Probe unavailable; no completed observation.")
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		fmt.Fprintln(os.Stderr, "Report write failed; no completed report.")
		os.Exit(1)
	}
	os.Exit(r.ExitCode)
}
