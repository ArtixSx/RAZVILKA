//go:build linux

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netresolve"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const d10NativeService = "my-independent-site"

// ROOT-only. Each case re-executes in fresh net/mount/PID namespaces, with no
// host interface or external default route. Public-format targets live in an
// owned backend netns joined by veth. The production checker, TLS, OS processes,
// adapter, Manager and rollback verifier are retained. This does not attest LAN/HIL.
func TestD10NativeAppManagerRollbackFreshC(t *testing.T) {
	if os.Getenv("RAZVILKA_D10_NATIVE") != "1" {
		t.Skip("ROOT-only: explicit native D10 opt-in and pinned Xray/Sing-box binaries")
	}
	if os.Getenv("RAZVILKA_D10_NATIVE_BACKEND") == "1" {
		d10NativeBackend(t)
		return
	}
	if os.Getenv("RAZVILKA_D10_NATIVE_CHILD") != "" {
		d10NativeChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires ROOT's exclusive Linux fixture host")
	}
	for _, name := range []string{"unshare", "ip", "iptables", "ip6tables", "iptables-save", "ip6tables-save"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"RAZVILKA_XRAY_NATIVE", "RAZVILKA_SINGBOX_NATIVE"} {
		p := os.Getenv(name)
		info, err := os.Stat(p)
		if !filepath.IsAbs(p) || err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			t.Fatal("requires pinned absolute executable", name)
		}
		want := "xray"
		if name == "RAZVILKA_SINGBOX_NATIVE" {
			want = "sing-box"
		}
		if filepath.Base(p) != want || strings.HasPrefix(filepath.Clean(p), "/opt/") {
			t.Fatal("receipt requires canonical basename and binary outside the private /opt mount", name)
		}
	}
	if st, err := os.Stat("/opt"); err != nil || !st.IsDir() {
		t.Fatal("/opt mount point must already exist; fixture never creates a host mount point")
	}
	if st, err := os.Stat("/run"); err != nil || !st.IsDir() {
		t.Fatal("/run mount point must already exist for private namespace handles")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ns := map[string]string{}
	for _, name := range []string{"net", "mnt", "pid"} {
		ns[name], err = os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Root authorized private diagnostics for this fully owned synthetic
	// fixture. Retain a dedicated 0700 directory after t.TempDir cleanup, so
	// Root can inspect exact redacted failure text instead of guessed labels.
	artifacts, err := os.MkdirTemp("", "razvilka-d10-private-")
	if err != nil {
		t.Fatal("private diagnostic directory", d10NativeErrorClass(err))
	}
	t.Log("private redacted failure artifacts:", artifacts)
	for _, scenario := range []string{"sing-box", "failure-exit"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			d10NativeCertificate(t, root)
			// Go's files resolver returns IPv4-mapped addresses. The real egress
			// pin deliberately refuses those; genuine DNS A responses retain IPv4.
			for name, data := range map[string]string{"hosts": "127.0.0.1 localhost\n", "resolv.conf": "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc", "--propagation", "private", exe,
				"-test.run=^TestD10NativeAppManagerRollbackFreshC$", "-test.v", "-test.timeout=3m30s")
			cmd.Env = append(os.Environ(), "RAZVILKA_D10_NATIVE_CHILD="+scenario, "RAZVILKA_D10_NATIVE_ROOT="+root,
				"RAZVILKA_D10_NATIVE_ARTIFACTS="+artifacts,
				"RAZVILKA_D10_PARENT_NET="+ns["net"], "RAZVILKA_D10_PARENT_MNT="+ns["mnt"], "RAZVILKA_D10_PARENT_PID="+ns["pid"],
				"SSL_CERT_FILE="+filepath.Join(root, "ca.pem"), "SSL_CERT_DIR="+filepath.Join(root, "empty-roots"),
				"GODEBUG="+strings.TrimRight(os.Getenv("GODEBUG"), ",")+",netdns=go")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("native child exceeded its bound; private PID namespace reaps owned descendants", ctx.Err())
			}
			if scenario == "failure-exit" {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatal("intentional failure must exit 1 after cleanup", err)
				}
				armed, readErr := os.ReadFile(filepath.Join(root, "failure.armed"))
				if readErr != nil || string(armed) != "ordinary native A committed\n" {
					t.Fatal("unexpected earlier failure cannot pass the failure-exit case", readErr)
				}
			} else if err != nil {
				t.Fatal("native child failed", err)
			}
			marker, readErr := os.ReadFile(filepath.Join(root, "cleanup.complete"))
			if readErr != nil || string(marker) != "processes stopped; kernel restored; TLS joined\n" {
				t.Fatal("native success/failure exit has no completed cleanup proof", readErr)
			}
		})
	}
}

func d10NativeCertificate(t *testing.T, root string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "owned D10 native fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"front.example", "service.example", "www.cloudflare.com", "api.ipify.org"}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{"ca.pem": {Type: "CERTIFICATE", Bytes: der}, "key.pem": {Type: "EC PRIVATE KEY", Bytes: private}} {
		if err := os.WriteFile(filepath.Join(root, name), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	clear(private)
}

func d10NativeCommand(ctx context.Context, tool string, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return exec.CommandContext(c, tool, args...).CombinedOutput()
}

// An actual namespace-local DNS server; it never forwards queries. No resolver
// function or checker dependency is replaced. Only three owned names have A
// records; AAAA returns a definitive empty answer and other names are NXDOMAIN.
func d10NativeDNS(t *testing.T) func() error {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Fatal("owned DNS listener", d10NativeErrorClass(err))
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				done <- err
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(buf[:n])
			if err != nil || header.Response || header.OpCode != 0 {
				continue
			}
			question, err := parser.Question()
			if err != nil {
				continue
			}
			if _, err := parser.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
				continue
			}
			owned := question.Class == dnsmessage.ClassINET && slices.Contains([]string{"service.example.", "www.cloudflare.com.", "api.ipify.org."}, strings.ToLower(question.Name.String()))
			response := dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionDesired: header.RecursionDesired}
			if !owned {
				response.RCode = dnsmessage.RCodeNameError
			}
			builder := dnsmessage.NewBuilder(nil, response)
			builder.EnableCompression()
			if err := builder.StartQuestions(); err != nil {
				done <- err
				return
			}
			if err := builder.Question(question); err != nil {
				done <- err
				return
			}
			if err := builder.StartAnswers(); err != nil {
				done <- err
				return
			}
			if owned && question.Type == dnsmessage.TypeA {
				if err := builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 12}}); err != nil {
					done <- err
					return
				}
			}
			wire, err := builder.Finish()
			if err == nil {
				_, err = conn.WriteToUDP(wire, peer)
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	var once sync.Once
	var joined error
	stop := func() error {
		once.Do(func() {
			_ = conn.Close()
			select {
			case err := <-done:
				if !errors.Is(err, net.ErrClosed) {
					joined = err
				}
			case <-time.After(3 * time.Second):
				joined = context.DeadlineExceeded
			}
		})
		return joined
	}
	// Early setup failure also closes and joins the listener. Main cleanup
	// calls the same idempotent function before writing its completion marker.
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error("owned DNS cleanup", d10NativeErrorClass(err))
		}
	})
	return stop
}

func d10NativeEndpointPreflight(t *testing.T, ctx context.Context) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, endpoint := range []struct {
		host, path, body string
		status           int
	}{{"www.cloudflare.com", "/cdn-cgi/trace", "ip=93.184.216.16\nwarp=off\n", http.StatusOK},
		{"api.ipify.org", "/", "93.184.216.16", http.StatusOK},
		{"service.example", "/generate_204", "", http.StatusNoContent}} {
		addresses, err := netresolve.LookupNetIP(ctx, "ip", endpoint.host)
		if err != nil || len(addresses) != 1 || !addresses[0].Is4() || addresses[0].Is4In6() || addresses[0].String() != "93.184.216.12" {
			t.Fatalf("owned DNS preflight: count=%d native-ipv4=%t error=%s", len(addresses), len(addresses) == 1 && addresses[0].Is4() && !addresses[0].Is4In6(), d10NativeErrorClass(err))
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+endpoint.host+endpoint.path, nil)
		if err != nil {
			t.Fatal("owned HTTPS request", d10NativeErrorClass(err))
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("owned verified HTTPS preflight", d10NativeErrorClass(err))
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
		_ = response.Body.Close()
		bodyMatch := string(body) == endpoint.body
		ok := readErr == nil && response.StatusCode == endpoint.status && bodyMatch && response.TLS != nil && len(response.TLS.VerifiedChains) > 0
		clear(body)
		if !ok {
			t.Fatalf("owned HTTPS preflight: status=%d verified-tls=%t body-match=%t error=%s", response.StatusCode, response.TLS != nil && len(response.TLS.VerifiedChains) > 0, bodyMatch, d10NativeErrorClass(readErr))
		}
	}
	t.Log("owned endpoints: genuine DNS A, verified HTTPS and expected direct-control/service responses")
}

// Compare semantic kernel configuration, without traffic counters or PIDs.
func d10NativeKernel(ctx context.Context) ([][]byte, error) {
	var result [][]byte
	for _, command := range [][]string{{"ip", "-4", "rule", "show"}, {"ip", "-6", "rule", "show"}, {"ip", "-4", "route", "show", "table", "all"},
		{"ip", "-6", "route", "show", "table", "all"}, {"iptables-save"}, {"ip6tables-save"}} {
		out, err := d10NativeCommand(ctx, command[0], command[1:]...)
		if err != nil || len(out) > 256<<10 {
			return nil, fmt.Errorf("bounded kernel readback %s: %w", command[0], err)
		}
		// iptables-save includes wall-clock comments that are not configuration.
		var lines []string
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(line, "#") {
				if strings.HasPrefix(line, ":") {
					// Policy-chain counters advance with genuine fixture traffic.
					// Keep the chain and policy verb; omit only the numeric counter.
					if at := strings.LastIndex(line, " ["); at > 0 && strings.HasSuffix(line, "]") {
						line = line[:at] + " [traffic-counter]"
					}
				}
				lines = append(lines, line)
			}
		}
		result = append(result, []byte(strings.Join(lines, "\n")))
	}
	return result, nil
}

type d10NativeProcesses struct {
	dataplane.OSProcessController
	mu         sync.Mutex
	specs      []dataplane.ProcessSpec
	failures   []string
	logCount   int
	afterStart func(dataplane.ProcessSpec) error
}

func (p *d10NativeProcesses) Start(ctx context.Context, spec dataplane.ProcessSpec) error {
	if err := p.OSProcessController.Start(ctx, spec); err != nil {
		p.recordFailure("start", err)
		return err
	}
	p.mu.Lock()
	p.specs = append(p.specs, spec)
	p.mu.Unlock()
	if p.afterStart != nil {
		return p.afterStart(spec)
	}
	return nil
}

func (p *d10NativeProcesses) Stop(ctx context.Context, spec dataplane.ProcessSpec) error {
	p.mu.Lock()
	index := p.logCount
	p.logCount++
	p.mu.Unlock()
	if index < 16 {
		if err := d10NativePrivateLog(spec.LogPath, fmt.Sprintf("client-%02d", index)); err != nil && !errors.Is(err, os.ErrNotExist) {
			p.recordFailure("private-log", err)
		}
	}
	err := p.OSProcessController.Stop(ctx, spec)
	if err != nil {
		p.recordFailure("stop", err)
	}
	return err
}

func (p *d10NativeProcesses) recordFailure(operation string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.failures) == 8 {
		p.failures = p.failures[1:]
	}
	p.failures = append(p.failures, operation+":"+d10NativeErrorClass(err))
}

// Forward every command unchanged to the adapter's original OS runner. Retain
// only bounded failure labels; command arguments and output are never logged.
type d10NativeRunner struct {
	base     dataplane.NFQWS2Runner
	mu       sync.Mutex
	failures []string
}

func (r *d10NativeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := r.base.Run(ctx, name, args...)
	if err != nil {
		tool := d10NativeLabel(filepath.Base(name), "ip", "iptables", "ip6tables", "sing-box", "xray")
		operation := "other"
		if len(args) > 0 {
			operation = d10NativeLabel(args[0], "check", "run", "version", "-4", "-6", "link", "route", "rule", "-t")
		}
		r.mu.Lock()
		if len(r.failures) == 8 {
			r.failures = r.failures[1:]
		}
		r.failures = append(r.failures, fmt.Sprintf("tool=%s operation=%s ipv6=%t error=%s output_class=%s", tool, operation, slices.Contains(args, "-6"), d10NativeErrorClass(err), d10NativeCauseCodes(string(out))))
		r.mu.Unlock()
	}
	return out, err
}

func d10NativeLabel(value string, allowed ...string) string {
	if slices.Contains(allowed, value) {
		return value
	}
	return "other"
}

// These labels describe persisted error text; they are NOT recovered typed
// causes. Only OS command/process observers above retain genuine error types.
func d10NativeCauseCodes(value string) string {
	if value == "" {
		return "none"
	}
	var codes []string
	for _, code := range []struct{ text, label string }{
		{"native validation failed", "native-validation"}, {"unknown field", "unknown-field"}, {"deprecated", "deprecated-schema"},
		{"legacy", "legacy-schema"}, {"with_gvisor", "gvisor-build"}, {"not installed", "binary-absent"},
		{"sidecar", "sidecar"}, {"forwarding", "forwarding"}, {"candidate probe", "candidate-service-probe"},
		{"candidate egress probe", "candidate-egress-probe"}, {"candidate transports failed", "candidate-transport"},
		{"exited before", "process-exited"}, {"did not become ready", "process-not-ready"}, {"certificate", "tls-certificate"},
		{"no such host", "dns-not-found"}, {"network is unreachable", "network-unreachable"}, {"operation not permitted", "permission"},
		{"policy", "policy"}, {"receipt", "receipt"}, {"cleanup", "cleanup"}, {"identity", "identity"},
		{"network epoch", "network-epoch"}, {"HTTP 403", "http-403"}, {"destination prefixes", "destinations-absent"},
		{"public address", "public-address-refusal"}, {"node-scoped", "node-scope"}, {"manifest", "manifest"},
		{"scoped node endpoint or service addresses changed", "node-endpoint-changed"}, {"selected/control TUN client proof", "tun-proof-required"},
		{"context deadline", "deadline"}, {"context canceled", "canceled"},
	} {
		if strings.Contains(value, code.text) && len(codes) < 8 {
			codes = append(codes, code.label)
		}
	}
	if len(codes) == 0 {
		return "unclassified"
	}
	return strings.Join(codes, ",")
}

func d10NativeApplyDiagnostic(t *testing.T, a *App, checks *d10NativeChecks, processes *d10NativeProcesses, runner *d10NativeRunner) {
	t.Helper()
	d10NativeCheckDiagnostic(t, checks, autonomyTestState(a))
	status, err := a.Dataplane.Status()
	d10NativePrivateFailure(t, status)
	t.Logf("D10 native journal: plan=%t execution=%t error_class=%s", status.Plan != nil, status.Execution != nil, d10NativeErrorClass(err))
	if plan := status.Plan; plan != nil {
		t.Logf("D10 native plan: ready=%t state=%s routes=%d adapters=%d blockers=%d", plan.Ready, d10NativeLabel(plan.State, "ready", "blocked", "canary-failed", "network-stale", "committed", "rolled-back", "rollback-failed", "applying"), len(plan.Routes), len(plan.Adapters), len(plan.Blockers))
	}
	if execution := status.Execution; execution != nil {
		t.Logf("D10 native execution: state=%s rollback_verified=%t steps=%d cause_codes=%s", d10NativeLabel(execution.State, "committed", "rolled-back", "rollback-failed", "canary-failed", "network-stale", "failed", "running", "applying", "rolling-back"), execution.RollbackVerified, len(execution.Steps), d10NativeCauseCodes(execution.Error))
		for i, step := range execution.Steps {
			if i == 16 {
				break
			}
			t.Logf("D10 native transaction[%d]: adapter=%s phase=%s state=%s cause_codes=%s", i, d10NativeLabel(step.Adapter, "sing-box", "xray", "lan-policy"), d10NativeLabel(step.Phase, "snapshot", "stage", "validate", "canary", "activate", "health", "commit-adapter", "rollback", "verify-rollback", "commit", "deactivate"), d10NativeLabel(step.State, "pending", "running", "passed", "failed", "ok", "done", "skipped"), d10NativeCauseCodes(step.Detail))
		}
	}
	processes.mu.Lock()
	for i, failure := range processes.failures {
		t.Logf("D10 native OS process failure[%d]: %s", i, failure)
	}
	processes.mu.Unlock()
	runner.mu.Lock()
	for i, failure := range runner.failures {
		t.Logf("D10 native OS command failure[%d]: %s", i, failure)
	}
	runner.mu.Unlock()
}

// Only the persisted transaction error and failed-step text are saved. No
// configuration, key, process log/output or HTTP response body is serialized.
func d10NativePrivateFailure(t *testing.T, status dataplane.RuntimeStatus) {
	t.Helper()
	if status.Execution == nil {
		return
	}
	dir, scenario := os.Getenv("RAZVILKA_D10_NATIVE_ARTIFACTS"), os.Getenv("RAZVILKA_D10_NATIVE_CHILD")
	info, err := os.Lstat(dir)
	if !filepath.IsAbs(dir) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || (scenario != "sing-box" && scenario != "failure-exit") {
		t.Error("private diagnostic destination refused")
		return
	}
	redact := d10NativeRedact
	payload := struct {
		Scenario         string   `json:"scenario"`
		State            string   `json:"state"`
		RollbackVerified bool     `json:"rollback_verified"`
		Error            string   `json:"redacted_execution_error"`
		FailedSteps      []string `json:"redacted_failed_steps"`
	}{Scenario: scenario, State: status.Execution.State, RollbackVerified: status.Execution.RollbackVerified, Error: redact(status.Execution.Error)}
	for _, step := range status.Execution.Steps {
		if step.State == "failed" && len(payload.FailedSteps) < 8 {
			payload.FailedSteps = append(payload.FailedSteps, d10NativeLabel(step.Phase, "snapshot", "stage", "validate", "canary", "activate", "health", "rollback", "verify-rollback", "commit-adapter")+": "+redact(step.Detail))
		}
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Error("private diagnostic encode", d10NativeErrorClass(err))
		return
	}
	defer clear(data)
	f, err := os.OpenFile(filepath.Join(dir, scenario+"-failure.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Error("private diagnostic write refused", d10NativeErrorClass(err))
		return
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Error("private diagnostic write incomplete")
	}
}

func d10NativeRedact(value string) string {
	root := os.Getenv("RAZVILKA_D10_NATIVE_ROOT")
	replacements := []string{root, "<fixture-root>", os.Getenv("RAZVILKA_XRAY_NATIVE"), "<pinned-xray>", os.Getenv("RAZVILKA_SINGBOX_NATIVE"), "<pinned-sing-box>",
		"/opt", "<private-opt>", "127.0.0.1", "<fixture-loopback>", "192.168.1.50", "<fixture-client>", "192.168.1.1", "<fixture-bridge>",
		"93.184.216.11", "<fixture-node-endpoint>", "93.184.216.12", "<fixture-service-ip>", "93.184.216.13", "<fixture-A-exit>", "93.184.216.14", "<fixture-B-exit>", "93.184.216.15", "<fixture-C-exit>",
		"93.184.216.16", "<fixture-direct-exit>", "192.0.2.1", "<fixture-backend-veth>", "192.0.2.2", "<fixture-router-veth>",
		"service.example", "<fixture-service-host>", "front.example", "<fixture-front-host>", "www.cloudflare.com", "<fixture-trace-host>", "api.ipify.org", "<fixture-ip-host>"}
	redactor := strings.NewReplacer(replacements...)
	urls := regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>]+`)
	uuid := regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	nodes := regexp.MustCompile(`\bnode-[a-f0-9]{64}\b`)
	paths := regexp.MustCompile(`/(?:opt|proc|sys|dev|etc|tmp|home|run|var)(?:/[a-zA-Z0-9_.-]+)*`)
	value = urls.ReplaceAllString(value, "<fixture-url>")
	value = uuid.ReplaceAllString(value, "<fixture-user>")
	value = nodes.ReplaceAllString(value, "<fixture-node-id>")
	value = redactor.Replace(value)
	value = paths.ReplaceAllString(value, "<path>")
	if len(value) > 4096 {
		value = value[:4096] + "<truncated>"
	}
	return value
}

// Keep only bounded ERROR/WARNING/FATAL lines from actual owned client/server
// logs before cleanup removes them. Full logs/configs/HTTP bodies are excluded.
func d10NativePrivateLog(path, label string) error {
	dir, scenario := os.Getenv("RAZVILKA_D10_NATIVE_ARTIFACTS"), os.Getenv("RAZVILKA_D10_NATIVE_CHILD")
	info, err := os.Lstat(dir)
	if !filepath.IsAbs(dir) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || (scenario != "sing-box" && scenario != "failure-exit") {
		return errors.New("private diagnostic destination refused")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("owned diagnostic log unavailable")
	}
	if _, err := f.Seek(max(0, info.Size()-8192), io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil {
		return err
	}
	defer clear(data)
	retained := make([]string, 0, 8)
	severity := regexp.MustCompile(`(?i)(error|warning|warn|fatal)`)
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	for _, line := range strings.Split(string(data), "\n") {
		if len(retained) == 8 {
			break
		}
		line = ansi.ReplaceAllString(line, "")
		lower := strings.ToLower(line)
		if !severity.MatchString(line) {
			continue
		}
		unsafe := false
		for _, forbidden := range []string{"-----begin", "private_key", "private key", "password", "secret", "token", "request body", "response body", "body=", "\"body\"", "\"uuid\""} {
			unsafe = unsafe || strings.Contains(lower, forbidden)
		}
		if !unsafe {
			line = d10NativeRedact(line)
			if len(line) > 1024 {
				line = line[:1024] + "<truncated>"
			}
			retained = append(retained, line)
		}
	}
	return d10NativePrivateReceipt(label, retained)
}

func d10NativePrivateReceipt(label string, retained []string) error {
	dir, scenario := os.Getenv("RAZVILKA_D10_NATIVE_ARTIFACTS"), os.Getenv("RAZVILKA_D10_NATIVE_CHILD")
	info, err := os.Lstat(dir)
	if !filepath.IsAbs(dir) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || (scenario != "sing-box" && scenario != "failure-exit") {
		return errors.New("private diagnostic destination refused")
	}
	payload, err := json.MarshalIndent(struct {
		Label string   `json:"label"`
		Lines []string `json:"redacted_error_lines"`
	}{label, retained}, "", "  ")
	if err != nil {
		return err
	}
	defer clear(payload)
	out, err := os.OpenFile(filepath.Join(dir, scenario+"-"+label+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := out.Write(payload)
	return errors.Join(writeErr, out.Sync(), out.Close())
}

func d10NativeKernelDiagnostic(t *testing.T, before, after [][]byte) {
	t.Helper()
	for i, category := range []string{"ipv4-rules", "ipv6-rules", "ipv4-routes", "ipv6-routes", "ipv4-firewall", "ipv6-firewall"} {
		if i >= len(before) || i >= len(after) {
			t.Logf("D10 native kernel diff: category=%s readback-incomplete=true", category)
			continue
		}
		if bytes.Equal(before[i], after[i]) {
			continue
		}
		oldLines, newLines := strings.FieldsFunc(string(before[i]), func(r rune) bool { return r == '\n' }), strings.FieldsFunc(string(after[i]), func(r rune) bool { return r == '\n' })
		slices.Sort(oldLines)
		slices.Sort(newLines)
		t.Logf("D10 native kernel diff: category=%s before_lines=%d after_lines=%d order_only=%t", category, len(oldLines), len(newLines), slices.Equal(oldLines, newLines))
		for direction, pair := range [][][]string{{oldLines, newLines}, {newLines, oldLines}} {
			counts := map[string]int{}
			for _, line := range pair[1] {
				counts[line]++
			}
			changed := map[string]int{}
			for _, line := range pair[0] {
				if counts[line] > 0 {
					counts[line]--
					continue
				}
				fields := strings.Fields(line)
				kind := "other"
				if len(fields) > 0 {
					kind = d10NativeLabel(fields[0], "local", "unicast", "unreachable", "blackhole", "multicast", "broadcast", "-A", "COMMIT", "*filter", "*mangle", "*nat")
					if strings.HasPrefix(fields[0], ":") {
						kind = "chain-policy"
					}
				}
				device, table, proto := "none", "implicit", "none"
				for j := 0; j+1 < len(fields); j++ {
					switch fields[j] {
					case "dev":
						device = d10NativeLabel(fields[j+1], "lo", "br0", "rz-sing", "rz-xray")
					case "table", "lookup":
						table = d10NativeLabel(fields[j+1], "local", "main", "default")
					case "proto":
						proto = d10NativeLabel(fields[j+1], "kernel", "boot", "static", "ra")
					}
				}
				key := fmt.Sprintf("kind=%s device=%s table=%s proto=%s expires=%t linkdown=%t", kind, device, table, proto, slices.Contains(fields, "expires"), slices.Contains(fields, "linkdown"))
				changed[key]++
			}
			var keys []string
			for key := range changed {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for j, key := range keys {
				if j == 8 {
					break
				}
				t.Logf("D10 native kernel delta: category=%s direction=%s count=%d %s", category, []string{"removed", "added"}[direction], changed[key], key)
			}
		}
	}
}

type d10NativeChecks struct {
	dataplane.NodeChecker
	before  func(context.Context, dataplane.NodeCheckRequest) error
	ids     []string
	results []dataplane.NodeCheckResult
	errors  []string
}

func (c *d10NativeChecks) Check(ctx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	if c.before != nil {
		if err := c.before(ctx, request); err != nil {
			return dataplane.NodeCheckResult{}, err
		}
	}
	c.ids = append(c.ids, request.NodeID)
	result, err := c.NodeChecker.Check(ctx, request)
	c.results = append(c.results, result)
	c.errors = append(c.errors, d10NativeErrorClass(err))
	return result, err
}

func d10NativeErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	for _, known := range []struct {
		err  error
		name string
	}{{context.Canceled, "canceled"}, {context.DeadlineExceeded, "deadline"},
		{dataplane.ErrExactNodeBusy, "checker-busy"}, {dataplane.ErrExactNodeUnavailable, "checker-unavailable"},
		{dataplane.ErrExactNodeRuntime, "runtime-unavailable"}, {dataplane.ErrExactNodeUnsupported, "unsupported"},
		{dataplane.ErrExactNodeNetworkChanged, "network-changed"}} {
		if errors.Is(err, known.err) {
			return known.name
		}
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Sprintf("process-exit-%d", exit.ExitCode())
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns-error"
	}
	var authority x509.UnknownAuthorityError
	if errors.As(err, &authority) {
		return "tls-unknown-authority"
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "tls-hostname"
	}
	// Type only: never format an error's URL, remote endpoint or process output.
	return fmt.Sprintf("type:%T", err)
}

// Explicit bounded diagnostic allowlist; no complete result/evidence DTO,
// requested URL, config, credentials, process output or response body.
func d10NativeCheckDiagnostic(t *testing.T, checks *d10NativeChecks, state autonomy.Runtime) {
	t.Helper()
	bound := func(value string, size int) string {
		if len(value) > size {
			return value[:size] + "..."
		}
		return value
	}
	t.Logf("D10 native checkpoint: checks=%d results=%d state=%q reason=%q failures=%d", len(checks.ids), len(checks.results), bound(state.State, 64), bound(state.Message, 512), state.Failures)
	start := max(0, len(checks.results)-8)
	for i := start; i < len(checks.results); i++ {
		r := checks.results[i]
		t.Logf("D10 native check[%d]: available=%t level=%q stage=%q code=%q verdict=%q engine=%q control=%q http=%d evidence_code=%q error_class=%q",
			i, r.Available, bound(r.TestLevel, 64), bound(r.Stage, 64), bound(r.ErrorCode, 96), bound(string(r.Verdict), 64), bound(r.Evidence.Engine, 64), bound(r.DirectControl, 64), r.HTTPStatus, bound(r.Evidence.ErrorCode, 96), bound(checks.errors[i], 96))
		for j, stage := range r.Stages {
			if j == 8 {
				break
			}
			t.Logf("D10 native phase[%d.%d]: id=%q status=%q duration_ms=%d", i, j, bound(stage.ID, 64), bound(stage.Status, 64), stage.Duration)
		}
	}
}

// Same constructors, roots, slot count and engine views as configuredNodeCheckers
// in cmd/razvilka. Only exported binary/WAN dependencies are bound here. No
// resolver, egress, service, identity or cleanup hook is replaced.
func d10NativeProductionExactDispatcher(root string, processes *d10NativeProcesses) (*dataplane.ExactNodeDispatcher, map[string]dataplane.NodeChecker, error) {
	sing := dataplane.NewExactNodeCheckerSlots(filepath.Join(root, "node-check"), 2)
	xray := dataplane.NewExactXrayNodeCheckerSlots(filepath.Join(root, "node-check-xray"), 2)
	sing.Binary, xray.Binary = os.Getenv("RAZVILKA_SINGBOX_NATIVE"), os.Getenv("RAZVILKA_XRAY_NATIVE")
	for _, checker := range []*dataplane.ExactNodeChecker{sing, xray} {
		checker.Processes, checker.FreshProfile = processes, stableNodeProfile
	}
	d, err := dataplane.NewExactNodeDispatcher(2, sing, xray)
	if err != nil {
		return nil, nil, err
	}
	views := map[string]dataplane.NodeChecker{}
	for _, engine := range []string{"sing-box", "xray"} {
		views[engine], err = d.ForEngine(engine)
		if err != nil {
			return nil, nil, err
		}
	}
	return d, views, nil
}

func d10NativeChild(t *testing.T) {
	root, scenario := os.Getenv("RAZVILKA_D10_NATIVE_ROOT"), os.Getenv("RAZVILKA_D10_NATIVE_CHILD")
	if os.Geteuid() != 0 || !filepath.IsAbs(root) || (scenario != "sing-box" && scenario != "failure-exit") {
		t.Fatal("invalid owned native child")
	}
	for _, name := range []string{"net", "mnt", "pid"} {
		actual, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil || actual == "" || actual == os.Getenv("RAZVILKA_D10_PARENT_"+strings.ToUpper(name)) {
			t.Fatal("refusing mutation without distinct owned namespace", name)
		}
	}
	links, err := net.Interfaces()
	if err != nil || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("native child must begin with only loopback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	opt := filepath.Join(root, "opt")
	for _, dir := range []string{opt, filepath.Join(root, "run"), filepath.Join(opt, "bin"), filepath.Join(opt, "etc", "razvilka"), filepath.Join(opt, "var", "lib", "razvilka")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Ubuntu can point /etc/resolv.conf into /run/systemd/resolve. Mirroring
	// only OUR fixture bytes preserves that symlink after the private /run bind;
	// copying host resolver data would defeat the isolated DNS boundary.
	for _, name := range []string{"hosts", "resolv.conf"} {
		target, err := filepath.EvalSymlinks(filepath.Join("/etc", name))
		if err != nil {
			t.Fatal("fixture mount target resolution", name, d10NativeErrorClass(err))
		}
		relative, err := filepath.Rel("/run", target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			continue // A target outside /run remains present in the private mount namespace.
		}
		private := filepath.Join(root, "run", relative)
		if err := os.MkdirAll(filepath.Dir(private), 0700); err != nil {
			t.Fatal("private fixture resolver parent", d10NativeErrorClass(err))
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || len(data) > 1024 {
			t.Fatal("owned fixture resolver bytes unavailable", d10NativeErrorClass(err))
		}
		err = os.WriteFile(private, data, 0600)
		clear(data)
		if err != nil {
			t.Fatal("private fixture resolver target", d10NativeErrorClass(err))
		}
	}
	// These bind mounts live only in the fresh private mount namespace.
	for _, mount := range [][2]string{{opt, "/opt"}, {filepath.Join(root, "run"), "/run"}, {filepath.Join(root, "hosts"), "/etc/hosts"}, {filepath.Join(root, "resolv.conf"), "/etc/resolv.conf"}} {
		if err := unix.Mount(mount[0], mount[1], "", unix.MS_BIND, ""); err != nil {
			t.Fatal("private fixture bind mount", err)
		}
	}
	for _, binary := range []string{os.Getenv("RAZVILKA_SINGBOX_NATIVE"), os.Getenv("RAZVILKA_XRAY_NATIVE")} {
		if err := os.Symlink(binary, filepath.Join("/opt/bin", filepath.Base(binary))); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", "/opt/bin:"+os.Getenv("PATH"))
	commands := [][]string{{"link", "set", "lo", "up"}, {"link", "add", "br0", "type", "bridge"}, {"link", "set", "br0", "up"}, {"addr", "add", "192.168.1.1/24", "dev", "br0"}}
	for _, ip := range []string{"93.184.216.16"} {
		commands = append(commands, []string{"addr", "add", ip + "/32", "dev", "lo"})
	}
	for _, args := range commands {
		if out, err := d10NativeCommand(ctx, "ip", args...); err != nil {
			t.Fatalf("owned fixture setup: %v %s", err, out)
		}
	}
	// Health reads the FIB for an actual LAN source with iif br0. Like the
	// native router fixture, this private namespace must permit IPv4 forwarding.
	// Set this before rp_filter: changing ip_forward resets IPv4 defaults.
	const forwarding = "/proc/sys/net/ipv4/ip_forward"
	beforeForwarding, err := os.ReadFile(forwarding)
	if err != nil || (strings.TrimSpace(string(beforeForwarding)) != "0" && strings.TrimSpace(string(beforeForwarding)) != "1") {
		t.Fatal("private router forwarding input unavailable", d10NativeErrorClass(err))
	}
	if err := os.WriteFile(forwarding, []byte("1\n"), 0600); err != nil {
		t.Fatal("private router forwarding setup", d10NativeErrorClass(err))
	}
	afterForwarding, err := os.ReadFile(forwarding)
	if err != nil || strings.TrimSpace(string(afterForwarding)) != "1" {
		t.Fatal("private router forwarding readback refused", d10NativeErrorClass(err))
	}
	t.Logf("owned router IPv4 forwarding: before=%s after=1", strings.TrimSpace(string(beforeForwarding)))
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/br0/disable_ipv6", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// iptables-nft -S can report virtual builtins without materializing a table.
	// Create/remove one empty fixture chain to instantiate real empty builtins
	// before the baseline. The later exact comparison ignores no table or row.
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"filter", "mangle", "nat"} {
			for _, operation := range []string{"-N", "-X"} {
				if out, err := d10NativeCommand(ctx, tool, "-t", table, operation, "RZ_D10_INIT"); err != nil {
					clear(out)
					t.Fatal("private firewall table preload", d10NativeErrorClass(err))
				}
			}
			save := tool + "-save"
			out, err := d10NativeCommand(ctx, save, "-t", table)
			materialized := err == nil && bytes.Contains(out, []byte("*"+table+"\n")) && bytes.Contains(out, []byte("COMMIT")) && !bytes.Contains(out, []byte("RZ_D10_INIT"))
			clear(out)
			if !materialized {
				t.Fatal("private firewall table did not materialize before baseline", d10NativeErrorClass(err))
			}
		}
	}
	kernelBase, err := d10NativeKernel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backendNamespace, stopBackendNamespace := d10NativeBackendTopology(t, ctx)
	stopDNS := d10NativeDNS(t)
	nodesPath := "/opt/etc/razvilka/nodes-private"
	if err := os.Mkdir(nodesPath, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodesPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	ports := map[string]int{}
	for port := 10443; port < 10446; port++ {
		snapshot, err := nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"},
			fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@93.184.216.11:%d?security=tls&sni=front.example", port), time.Now(), time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range snapshot.Nodes {
			if _, exists := ports[n.ID]; !exists {
				ports[n.ID] = port
			}
		}
	}
	var ids []string
	for id := range ports {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) != 3 {
		t.Fatal("expected three distinct genuine nodes")
	}
	var backend *exec.Cmd
	backendDone := make(chan error, 1)
	processes := &d10NativeProcesses{}
	var adapter *dataplane.ProxyTunnelAdapter
	var runner *d10NativeRunner
	var dispatch *dataplane.ExactNodeDispatcher
	// Registered before any process starts; runs even on a failed assertion.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		ok := true
		if adapter != nil {
			if err := adapter.Deactivate(cleanup); err != nil {
				t.Errorf("native adapter cleanup: %v", err)
				ok = false
			}
		}
		if dispatch != nil {
			if err := dispatch.Recover(cleanup); err != nil {
				t.Errorf("exact checker cleanup: %v", err)
				ok = false
			}
		}
		if backend != nil && backend.Process != nil {
			if err := os.WriteFile(filepath.Join(root, "backend.stop"), []byte("stop\n"), 0600); err != nil {
				t.Error("owned backend stop request", d10NativeErrorClass(err))
				ok = false
			}
			select {
			case err := <-backendDone:
				if err != nil {
					t.Error("owned backend exit", d10NativeErrorClass(err))
					ok = false
				}
			case <-time.After(10 * time.Second):
				_ = backend.Process.Kill()
				select {
				case <-backendDone:
				case <-cleanup.Done():
					t.Error("owned backend was not reaped")
				}
				t.Error("owned backend exceeded graceful cleanup bound")
				ok = false
			}
			marker, err := os.ReadFile(filepath.Join(root, "backend-cleanup.complete"))
			if err != nil || string(marker) != "owned VLESS stopped; HTTPS joined\n" {
				t.Error("owned backend lacks real process/TLS cleanup receipt")
				ok = false
			}
		}
		if err := stopBackendNamespace(); err != nil {
			t.Error("owned remote namespace/veth cleanup", d10NativeErrorClass(err))
			ok = false
		}
		if err := stopDNS(); err != nil {
			t.Error("DNS fixture did not join", d10NativeErrorClass(err))
			ok = false
		}
		processes.mu.Lock()
		for _, spec := range processes.specs {
			if processes.Running(spec) {
				t.Error("owned process survived cleanup", spec.ID)
				ok = false
			}
		}
		processes.mu.Unlock()
		after, err := d10NativeKernel(cleanup)
		if err != nil || !reflect.DeepEqual(after, kernelBase) {
			d10NativeKernelDiagnostic(t, kernelBase, after)
			t.Error("native kernel configuration was not restored", err)
			ok = false
		}
		for _, name := range []string{"rz-sing", "rz-xray"} {
			if _, err := net.InterfaceByName(name); err == nil {
				t.Error("owned TUN survived cleanup", name)
				ok = false
			}
		}
		if ok {
			if err := os.WriteFile(filepath.Join(root, "cleanup.complete"), []byte("processes stopped; kernel restored; TLS joined\n"), 0600); err != nil {
				t.Error(err)
			}
		}
	})
	orderedPorts := []int{ports[ids[0]], ports[ids[1]], ports[ids[2]]}
	data, err := json.Marshal(orderedPorts)
	if err != nil {
		t.Fatal("owned backend node order", d10NativeErrorClass(err))
	}
	err = os.WriteFile(filepath.Join(root, "backend-ports.json"), data, 0600)
	clear(data)
	if err != nil {
		t.Fatal("owned backend binding write", d10NativeErrorClass(err))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	routerNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	backend = exec.Command("ip", "netns", "exec", backendNamespace, exe, "-test.run=^TestD10NativeAppManagerRollbackFreshC$", "-test.v", "-test.timeout=3m30s")
	backend.Env = append(os.Environ(), "RAZVILKA_D10_NATIVE_BACKEND=1", "RAZVILKA_D10_ROUTER_NET="+routerNamespace)
	backend.Stdout, backend.Stderr = os.Stdout, os.Stderr
	if err := backend.Start(); err != nil {
		t.Fatal("owned remote backend start", d10NativeErrorClass(err))
	}
	go func() { backendDone <- backend.Wait() }()
	ready := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		marker, err := os.ReadFile(filepath.Join(root, "backend.ready"))
		if err == nil && string(marker) == "real TLS and VLESS ready\n" {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("owned remote backend readiness absent")
	}
	d10NativeEndpointPreflight(t, ctx)
	store, err := config.Load("/opt/etc/razvilka/config.json")
	if err != nil {
		t.Fatal(err)
	}
	const engine = "sing-box"
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService(d10NativeService, config.ServiceState{Enabled: false, Route: engine}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	// Explicit active draft intent precedes automation; committed A is still
	// cold and is created only by the ordinary App/Manager transaction below.
	if err := store.UpdateService(d10NativeService, config.ServiceState{Enabled: true, Route: engine}); err != nil {
		t.Fatal(err)
	}
	state := "/opt/var/lib/razvilka/dataplane"
	configs := engineconfig.New("/opt/var/lib/razvilka/drafts", "/opt/var/lib/razvilka/backups")
	service := catalog.Service{ID: d10NativeService, Name: "Owned native D10 service", Category: "other", Strategy: []string{engine},
		Domains: []string{"service.example"}, ProbeURL: "https://service.example/generate_204",
		Probes: []catalog.Probe{{ID: "native-web", Label: "Owned HTTPS service", URL: "https://service.example/generate_204", Required: true,
			Expect: catalog.ProbeExpectation{StatusCodes: []int{http.StatusNoContent}, RedirectPolicy: "none"}}}}
	cat := catalog.Catalog{Services: []catalog.Service{service}}
	if err := catalog.Validate(cat); err != nil {
		t.Fatal("native catalog must pass the ordinary startup validator", err)
	}
	a := &App{Store: store, Nodes: nodes, EngineConfigs: configs, FreshProfile: stableNodeProfile, Dataplane: dataplane.New(state), Catalog: cat}
	a.Dataplane.FreshProfile = stableNodeProfile
	adapter, err = dataplane.NewProxyTunnelAdapter(engine, configs, state)
	if err != nil {
		t.Fatal(err)
	}
	adapter.EngineBin, adapter.SidecarBin, adapter.Processes = os.Getenv("RAZVILKA_SINGBOX_NATIVE"), os.Getenv("RAZVILKA_SINGBOX_NATIVE"), processes
	runner = &d10NativeRunner{base: adapter.Runner}
	adapter.Runner = runner
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	err = a.Dataplane.ConfigureSingBoxNodeRoutes(func(c context.Context, req []dataplane.NodeRouteRequest, profile string, at time.Time) (dataplane.NodeRouteMaterial, error) {
		bindings := make([]nodestore.RouteBinding, len(req))
		for i, r := range req {
			bindings[i] = nodestore.RouteBinding{ServiceID: r.ServiceID, NodeID: r.NodeID, NetworkProfile: profile, Domains: r.Domains, Destinations: r.Destinations}
		}
		m, err := nodes.MaterializeSingBox(c, bindings, at)
		return dataplane.NodeRouteMaterial{Config: m.Config, EndpointHosts: m.EndpointHosts}, err
	}, stableNodeProfile)
	if err != nil {
		t.Fatal(err)
	}
	var views map[string]dataplane.NodeChecker
	dispatch, views, err = d10NativeProductionExactDispatcher(state, processes)
	if err != nil {
		t.Fatal(err)
	}
	checks := &d10NativeChecks{NodeChecker: views[engine]}
	views[engine] = checks
	a.NodeChecker, a.NodeCheckers = views["sing-box"], views
	p := autonomy.Default()
	p.Enabled, p.SetupComplete, p.InheritNewServices = true, true, true
	p.DefaultSources, p.SourceIDs, p.PreferredRoutes = []string{"192.168.1.50/32"}, []string{"manual"}, nil
	p.ReserveTarget, p.CandidatesPerRound, p.FailureConfirmSeconds = 2, 3, 10
	p.Application.Mode, p.Components.Mode = "off", "off"
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest("PUT", "/api/v1/autonomy", map[string]any{"expected_revision": 0, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": true}))
	if w.Code != 200 {
		t.Fatal("real consent failed", w.Code, w.Body.String())
	}
	if err := a.inheritAutonomyService(ctx, d10NativeService); err != nil {
		t.Fatal(err)
	}
	a.autonomyRound(ctx, time.Now())
	first := autonomyTestState(a)
	if !reflect.DeepEqual(checks.ids, ids[:1]) || len(checks.results) != 1 || !checks.results[0].Available ||
		checks.results[0].Evidence.Engine != engine || checks.results[0].EgressIP != "93.184.216.13" || checks.results[0].DirectControl != "measured" {
		d10NativeCheckDiagnostic(t, checks, first)
		t.Fatal("first node lacks genuine exact engine/service/paired TLS proof", first.State)
	}
	if first.State != "applied" || selectedRoute(store.Get().AppliedServices[d10NativeService]) != engine+":"+ids[0] {
		d10NativeApplyDiagnostic(t, a, checks, processes, runner)
		t.Fatal("ordinary App/Manager did not commit native A", first.State)
	}
	if scenario == "failure-exit" {
		if err := os.WriteFile(filepath.Join(root, "failure.armed"), []byte("ordinary native A committed\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Error("intentional D10 fixture failure after real A commit; parent requires completed cleanup and exit 1")
		return
	}
	base := store.Get()
	planA, exists, err := a.Dataplane.Committed()
	if err != nil || !exists {
		t.Fatal("A committed journal missing", err)
	}
	kernelA, err := d10NativeKernel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tunA, err := d10NativeOwnedTUN(ctx, filepath.Join(adapter.StateRoot, "runtime", "engine.json"))
	if err != nil {
		t.Fatal("A owned TUN identity readback", d10NativeErrorClass(err))
	}
	filesA := map[string][]byte{}
	for _, name := range []string{"runtime/engine.json", "runtime/sidecar.json", "policy.json", "policy-generation.json"} {
		filesA[name], err = os.ReadFile(filepath.Join(adapter.StateRoot, name))
		if err != nil {
			t.Fatal("A runtime snapshot", err)
		}
		defer clear(filesA[name])
	}
	rollbackSeen := false
	var failedB dataplane.Execution
	checks.before = func(c context.Context, req dataplane.NodeCheckRequest) error {
		if req.NodeID != ids[2] {
			return nil
		}
		refuse := func(code string, cause error) error {
			t.Log("fresh C observer refused:", code)
			if cause != nil {
				if err := d10NativePrivateReceipt("rollback-observer", []string{code + ": " + d10NativeRedact(cause.Error())}); err != nil {
					t.Error("private rollback observer receipt", d10NativeErrorClass(err))
				}
			}
			return errors.New(code)
		}
		status, err := a.Dataplane.Status()
		if err != nil || status.Execution == nil || status.Plan == nil || status.Execution.State != "rolled-back" || !status.Execution.RollbackVerified {
			return refuse("fresh C preceded verified native rollback journal", err)
		}
		failedB = *status.Execution
		committed, exists, err := a.Dataplane.Committed()
		if err != nil || !exists || !reflect.DeepEqual(committed, planA) || !reflect.DeepEqual(store.Get(), base) {
			t.Logf("fresh C restoration flags: committed-exists=%t plan-equal=%t config-equal=%t", exists, reflect.DeepEqual(committed, planA), reflect.DeepEqual(store.Get(), base))
			return refuse("fresh C preceded exact A config/committed restoration", err)
		}
		confirmed, err := adapter.VerifyRollback(c, *status.Plan, filepath.Join(state, "transactions", failedB.PlanID, engine))
		if err != nil || !confirmed {
			return refuse("independent production VerifyRollback rejected A", err)
		}
		for name, expected := range filesA {
			actual, err := os.ReadFile(filepath.Join(adapter.StateRoot, name))
			match := err == nil && bytes.Equal(actual, expected)
			if err == nil && name == "policy-generation.json" {
				err = d10NativeRestoredBinding(expected, actual, filepath.Join(state, "transactions", failedB.PlanID, engine))
				match = err == nil
			}
			clear(actual)
			if !match {
				t.Log("fresh C restored file refused:", name)
				return refuse("restored native A files differ", err)
			}
		}
		kernel, err := d10NativeKernel(c)
		if err == nil {
			var tun d10NativeTUNIdentity
			tun, err = d10NativeOwnedTUN(c, filepath.Join(adapter.StateRoot, "runtime", "engine.json"))
			if err == nil {
				err = d10NativeRestoredKernel(kernelA, kernel, tunA, tun)
			}
		}
		if err != nil {
			d10NativeKernelDiagnostic(t, kernelA, kernel)
			d10NativeIPv6RollbackReceipt(t, kernelA, kernel, filepath.Join(adapter.StateRoot, "runtime", "engine.json"))
			return refuse("restored native A kernel differs", err)
		}
		rollbackSeen = true
		return nil
	}
	processes.afterStart = func(spec dataplane.ProcessSpec) error {
		if spec.ID != "sing-box-engine" {
			return nil
		}
		data, err := os.ReadFile(spec.MatchArg)
		if err != nil {
			return err
		}
		defer clear(data)
		var doc struct {
			Outbounds []struct {
				Type string `json:"type"`
				Port int    `json:"server_port"`
			} `json:"outbounds"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return errors.New("actual runtime config unreadable")
		}
		for _, out := range doc.Outbounds {
			if out.Type == "vless" && out.Port == ports[ids[1]] {
				// Actual process start is after isolated checker+Canary, before live
				// Health. Change only the owned remote server's response, not results.
				return os.WriteFile(filepath.Join(root, "block-b"), []byte("live B rejects\n"), 0600)
			}
		}
		return nil
	}
	if err := os.WriteFile(filepath.Join(root, "block-a"), []byte("live A rejects\n"), 0600); err != nil {
		t.Fatal("owned remote A failure request", d10NativeErrorClass(err))
	}
	d10NativeDue(a)
	a.autonomyRound(ctx, time.Now())
	if r := autonomyTestState(a); r.Failures != 1 || !reflect.DeepEqual(store.Get(), base) {
		t.Fatal("first real A rejection did not retain quorum/config", r.State)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(11 * time.Second): // Real failure-confirm interval; no forged observation timestamps.
	}
	d10NativeDue(a)
	a.autonomyRound(ctx, time.Now())
	final := autonomyTestState(a)
	if !rollbackSeen || final.State != "applied" || selectedRoute(store.Get().AppliedServices[d10NativeService]) != engine+":"+ids[2] ||
		len(final.CandidateFailures) != 1 || final.CandidateFailures[0].NodeID != ids[1] || final.CandidateFailures[0].Code != "http-403" ||
		!reflect.DeepEqual(checks.ids, []string{ids[0], ids[0], ids[0], ids[1], ids[2]}) {
		d10NativeApplyDiagnostic(t, a, checks, processes, runner)
		t.Fatal("native B failure/verified A rollback/fresh C chain not complete", final.State, checks.ids)
	}
	if !checks.results[len(checks.results)-1].Available || checks.results[len(checks.results)-1].EgressIP != "93.184.216.15" {
		t.Fatal("C did not produce real native service proof")
	}
	failedHealth := 0
	for _, step := range failedB.Steps {
		if step.State == "failed" {
			if step.Adapter != engine || step.Phase != "health" {
				t.Fatal("failure was not live candidate Health")
			}
			failedHealth++
		}
	}
	if failedHealth != 1 || len(final.Switches) != 3 || !sameNodeRecoveryStrings(store.Get().AppliedServices[d10NativeService].Sources, base.AppliedServices[d10NativeService].Sources) {
		t.Fatal("native attribution/budget/scope changed")
	}
	for id, expected := range base.Services {
		if id != d10NativeService && !reflect.DeepEqual(store.Get().Services[id], expected) {
			t.Fatal("native apply changed a foreign draft", id)
		}
	}
	for id, expected := range base.AppliedServices {
		if id != d10NativeService && !reflect.DeepEqual(store.Get().AppliedServices[id], expected) {
			t.Fatal("native apply changed a foreign applied service", id)
		}
	}
	status, err := a.Dataplane.Status()
	if err != nil || status.Execution == nil || status.Execution.State != "committed" {
		t.Fatal("C transaction did not commit", err)
	}
	t.Log("genuine SG exact/canary B PASS -> real live HTTP403 -> production rollback+read-only VerifyRollback A -> fresh exact C -> ordinary App/Manager commit; cleanup readback follows")
}

// Advance only the scheduler eligibility; checks, quorum timestamps and expiry
// keep real wall time. The ten-second failure confirmation is actually waited.
func d10NativeDue(a *App) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	r := a.autonomy.doc.Runtime[d10NativeService]
	r.NextCheck = time.Time{}
	a.autonomy.doc.Runtime[d10NativeService] = r
}

type d10NativeTUNIdentity struct {
	Name       string
	Index      int
	Up         bool
	Generation int
	Addresses  []netip.Prefix
	Configured []netip.Prefix
}

// Read the actual owned live interface and its exact configured addresses.
// This is fixture verification after production VerifyRollback, not authority.
func d10NativeOwnedTUN(ctx context.Context, enginePath string) (d10NativeTUNIdentity, error) {
	var identity d10NativeTUNIdentity
	if err := ctx.Err(); err != nil {
		return identity, err
	}
	file, err := os.Open(enginePath)
	if err != nil {
		return identity, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	defer clear(data)
	if readErr != nil || closeErr != nil || len(data) > 1<<20 {
		return identity, errors.New("bounded owned TUN config unavailable")
	}
	var doc struct {
		Inbounds []struct {
			Type      string   `json:"type"`
			Interface string   `json:"interface_name"`
			Address   []string `json:"address"`
			IPv4      string   `json:"inet4_address"`
			IPv6      string   `json:"inet6_address"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return identity, errors.New("owned TUN config unreadable")
	}
	owned := 0
	for _, inbound := range doc.Inbounds {
		if inbound.Type != "tun" || inbound.Interface != "rz-sing" {
			continue
		}
		owned++
		for _, raw := range append(inbound.Address, inbound.IPv4, inbound.IPv6) {
			if raw == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || len(identity.Configured) >= 24 {
				return identity, errors.New("owned TUN configured address refused")
			}
			identity.Configured = append(identity.Configured, prefix)
		}
	}
	if owned != 1 || len(identity.Configured) == 0 {
		return identity, errors.New("exact owned TUN config unavailable")
	}
	link, err := net.InterfaceByName("rz-sing")
	if err != nil {
		return identity, err
	}
	identity.Name, identity.Index, identity.Up = link.Name, link.Index, link.Flags&net.FlagUp != 0
	addresses, err := link.Addrs()
	if err != nil || len(addresses) > 24 {
		return identity, errors.New("bounded owned TUN addresses unavailable")
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return identity, errors.New("owned TUN address unreadable")
		}
		identity.Addresses = append(identity.Addresses, prefix)
	}
	mode, err := os.ReadFile("/proc/sys/net/ipv6/conf/rz-sing/addr_gen_mode")
	if err != nil || len(mode) > 8 {
		return identity, errors.New("owned TUN address generation unavailable")
	}
	identity.Generation, err = strconv.Atoi(strings.TrimSpace(string(mode)))
	if err != nil {
		return identity, errors.New("owned TUN address generation unreadable")
	}
	return identity, ctx.Err()
}

// Native163 proved regeneration of exactly one kernel link-local local host
// route after restoring the owned TUN. Permit only that address substitution,
// witnessed in both actual interfaces; preserve all other bytes and qualifiers.
func d10NativeRestoredKernel(before, after [][]byte, old, current d10NativeTUNIdentity) error {
	refused := errors.New("restored owned TUN/kernel identity differs")
	if len(before) != 6 || len(after) != 6 {
		return refused
	}
	for i := range before {
		if i != 3 && !bytes.Equal(before[i], after[i]) {
			return refused
		}
	}
	linkLocal := netip.MustParsePrefix("fe80::/64")
	address := func(identity d10NativeTUNIdentity) (netip.Addr, bool) {
		if identity.Name != "rz-sing" || identity.Index <= 0 || !identity.Up ||
			(identity.Generation != 0 && identity.Generation != 2 && identity.Generation != 3) ||
			len(identity.Configured) == 0 || len(identity.Configured) > 24 || len(identity.Addresses) > 24 {
			return netip.Addr{}, false
		}
		for i, prefix := range identity.Configured {
			if !prefix.IsValid() || prefix.Addr().IsLinkLocalUnicast() || prefix.Overlaps(linkLocal) ||
				!slices.Contains(identity.Addresses, prefix) || slices.Contains(identity.Configured[:i], prefix) {
				return netip.Addr{}, false
			}
		}
		var local netip.Addr
		for i, prefix := range identity.Addresses {
			if !prefix.IsValid() || slices.Contains(identity.Addresses[:i], prefix) {
				return netip.Addr{}, false
			}
			if prefix.Addr().IsLinkLocalUnicast() {
				if local.IsValid() || prefix.Bits() != 64 || !linkLocal.Contains(prefix.Addr()) {
					return netip.Addr{}, false
				}
				local = prefix.Addr()
			} else if !slices.Contains(identity.Configured, prefix) {
				return netip.Addr{}, false
			}
		}
		return local, local.IsValid()
	}
	oldAddress, oldOK := address(old)
	newAddress, newOK := address(current)
	if !oldOK || !newOK || old.Generation != current.Generation || !slices.Equal(old.Configured, current.Configured) ||
		(oldAddress != newAddress && old.Index == current.Index) {
		return refused
	}
	normalize := func(data []byte, actual netip.Addr) ([]byte, bool) {
		lines := strings.Split(string(data), "\n")
		matched := 0
		for i, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "local" || fields[1] != actual.String() {
				continue
			}
			if len(fields) != 12 || !slices.Equal(fields[2:], []string{"dev", "rz-sing", "table", "local", "proto", "kernel", "metric", "0", "pref", "medium"}) {
				return nil, false
			}
			matched++
			lines[i] = strings.Replace(line, fields[1], "<owned-generated-link-local>", 1)
		}
		return []byte(strings.Join(lines, "\n")), matched == 1
	}
	oldRoutes, oldOK := normalize(before[3], oldAddress)
	newRoutes, newOK := normalize(after[3], newAddress)
	if !oldOK || !newOK || !bytes.Equal(oldRoutes, newRoutes) {
		return refused
	}
	return nil
}

func TestD10NativeRestoredKernelRejectsUnwitnessedOrForeignIPv6Changes(t *testing.T) {
	oldLL, newLL := "fe80::5efc:71cb:5211:a24a", "fe80::b9be:bb67:dd9e:c61b"
	route := func(address string) string {
		return "local " + address + " dev rz-sing table local proto kernel metric 0 pref medium\n"
	}
	configured := []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30"), netip.MustParsePrefix("fd00:19::1/126")}
	witness := func(address string, index int) d10NativeTUNIdentity {
		return d10NativeTUNIdentity{Name: "rz-sing", Index: index, Up: true, Generation: 3,
			Configured: slices.Clone(configured), Addresses: append(slices.Clone(configured), netip.MustParsePrefix(address+"/64"))}
	}
	kernel := func(address string) [][]byte {
		return [][]byte{[]byte("ipv4 rules\n"), []byte("ipv6 rules\n"), []byte("ipv4 routes\n"),
			[]byte("fd00:19::/126 dev rz-sing proto kernel metric 256 pref medium\n" +
				"local fd00:19::1 dev rz-sing table local proto kernel metric 0 pref medium\n" + route(address)),
			[]byte("ipv4 firewall\n"), []byte("ipv6 firewall\n")}
	}
	for _, tc := range []struct {
		name    string
		allowed bool
		change  func([][]byte, *d10NativeTUNIdentity)
	}{
		{"witnessed-recreated-owned-link-local", true, func([][]byte, *d10NativeTUNIdentity) {}},
		{"unchanged-link-local", true, func(k [][]byte, w *d10NativeTUNIdentity) { k[3] = kernel(oldLL)[3]; *w = witness(oldLL, 8) }},
		{"unwitnessed-route-address", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), newLL, "fe80::99"))
		}},
		{"same-interface-generation", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Index = 5 }},
		{"foreign-interface-witness", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Name = "br0" }},
		{"missing-interface-witness", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Index = 0 }},
		{"interface-down", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Up = false }},
		{"no-kernel-address-generation", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Generation = 1 }},
		{"address-generation-changed", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Generation = 2 }},
		{"missing-live-address", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Addresses = slices.Clone(configured) }},
		{"extra-live-link-local", false, func(_ [][]byte, w *d10NativeTUNIdentity) {
			w.Addresses = append(w.Addresses, netip.MustParsePrefix("fe80::99/64"))
		}},
		{"wrong-live-prefix", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Addresses[2] = netip.MustParsePrefix(newLL + "/128") }},
		{"explicit-link-local-configured", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Configured = append(w.Configured, w.Addresses[2]) }},
		{"configured-ipv6-changed", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Configured[1] = netip.MustParsePrefix("fd00:20::1/126") }},
		{"configured-ipv6-address-missing", false, func(_ [][]byte, w *d10NativeTUNIdentity) { w.Addresses = append(w.Addresses[:1], w.Addresses[2:]...) }},
		{"foreign-device-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), "local "+newLL+" dev rz-sing", "local "+newLL+" dev br0"))
		}},
		{"foreign-table-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), "table local", "table main"))
		}},
		{"non-kernel-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), "proto kernel", "proto static"))
		}},
		{"changed-metric", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), "metric 0", "metric 1"))
		}},
		{"changed-preference", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), "pref medium", "pref high"))
		}},
		{"extra-route-qualifier", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), route(newLL), strings.TrimSuffix(route(newLL), "\n")+" linkdown\n"))
		}},
		{"missing-link-local-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), route(newLL), ""))
		}},
		{"duplicate-link-local-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) { k[3] = append(k[3], []byte(route(newLL))...) }},
		{"extra-foreign-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = append(k[3], []byte("local fe80::99 dev br0 table local proto kernel metric 0 pref medium\n")...)
		}},
		{"missing-configured-ipv6-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), "fd00:19::/126 dev rz-sing proto kernel metric 256 pref medium\n", ""))
		}},
		{"changed-configured-ipv6-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) {
			k[3] = []byte(strings.ReplaceAll(string(k[3]), "fd00:19::1", "fd00:19::2"))
		}},
		{"extra-ipv6-rule", false, func(k [][]byte, _ *d10NativeTUNIdentity) { k[1] = append(k[1], []byte("foreign rule\n")...) }},
		{"changed-ipv4-route", false, func(k [][]byte, _ *d10NativeTUNIdentity) { k[2] = []byte("changed ipv4 routes\n") }},
		{"changed-ipv6-firewall", false, func(k [][]byte, _ *d10NativeTUNIdentity) { k[5] = []byte("changed firewall\n") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := kernel(oldLL), kernel(newLL)
			old, current := witness(oldLL, 5), witness(newLL, 8)
			tc.change(after, &current)
			if err := d10NativeRestoredKernel(before, after, old, current); (err == nil) != tc.allowed {
				t.Fatalf("restored kernel allowed=%t, want=%t", err == nil, tc.allowed)
			}
		})
	}
}

func d10NativeIPv6RollbackReceipt(t *testing.T, before, after [][]byte, enginePath string) {
	t.Helper()
	if len(before) <= 3 || len(after) <= 3 {
		return
	}
	var retained []string
	for _, direction := range []struct {
		label    string
		from, to []byte
	}{{"removed IPv6 route", before[3], after[3]}, {"added IPv6 route", after[3], before[3]}} {
		counts := map[string]int{}
		for _, line := range strings.Split(string(direction.to), "\n") {
			counts[line]++
		}
		count := 0
		for _, line := range strings.Split(string(direction.from), "\n") {
			if counts[line] > 0 {
				counts[line]--
				continue
			}
			if strings.TrimSpace(line) == "" || count == 8 {
				continue
			}
			redacted := d10NativeRedact(line)
			if len(redacted) > 1024 {
				redacted = redacted[:1024] + "<truncated>"
			}
			retained = append(retained, direction.label+": "+redacted)
			count++
		}
	}
	f, err := os.Open(enginePath)
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		_ = f.Close()
		var doc struct {
			Inbounds []struct {
				Type      string   `json:"type"`
				Interface string   `json:"interface_name"`
				Address   []string `json:"address"`
				IPv4      string   `json:"inet4_address"`
				IPv6      string   `json:"inet6_address"`
			} `json:"inbounds"`
		}
		if readErr == nil && len(data) <= 1<<20 && json.Unmarshal(data, &doc) == nil {
			for _, inbound := range doc.Inbounds {
				if inbound.Type == "tun" && inbound.Interface == "rz-sing" {
					for _, address := range append(inbound.Address, inbound.IPv4, inbound.IPv6) {
						if _, err := netip.ParsePrefix(address); err == nil && len(retained) < 24 {
							retained = append(retained, "configured owned TUN address: "+address)
						}
					}
				}
			}
		}
		clear(data)
	}
	if err := d10NativePrivateReceipt("ipv6-rollback", retained); err != nil {
		t.Error("private IPv6 rollback receipt", d10NativeErrorClass(err))
	}
}

// Restoration issues fresh addition authority instead of reviving a consumed
// receipt. Policy/runtime bytes must still match A.
func d10NativeRestoredBinding(before, after []byte, transaction string) error {
	type binding struct {
		Schema     int    `json:"schema"`
		Engine     string `json:"engine"`
		Digest     string `json:"policy_sha256"`
		Generation string `json:"generation"`
		ReceiptID  string `json:"receipt_id,omitempty"`
		Phase      string `json:"phase"`
	}
	decode := func(data []byte) (binding, error) {
		var value binding
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if len(data) > 4096 || d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF {
			return value, errors.New("restoration binding encoding refused")
		}
		canonical, _ := json.Marshal(value)
		id := regexp.MustCompile(`^[a-f0-9]{32}$`)
		if !bytes.Equal(data, canonical) || value.Schema != 1 || value.Engine != "sing-box" || value.Phase != "active" ||
			!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(value.Digest) || !id.MatchString(value.Generation) || !id.MatchString(value.ReceiptID) {
			return value, errors.New("restoration binding identity refused")
		}
		return value, nil
	}
	old, err := decode(before)
	if err != nil {
		return err
	}
	current, err := decode(after)
	if err != nil {
		return err
	}
	if current.Digest != old.Digest || current.Generation == old.Generation || current.ReceiptID == old.ReceiptID {
		return errors.New("restoration did not retain A policy with fresh receipt")
	}
	data, err := os.ReadFile(filepath.Join(transaction, "policy-additions.json"))
	if err != nil || len(data) > 4096 {
		return errors.New("restoration transaction receipt unavailable")
	}
	defer clear(data)
	// Production VerifyRollback just validated the checksummed complete receipt.
	// Independently require its exact restoration reference here.
	var receipt struct {
		Schema                int
		Engine, Phase         string
		RestorationGeneration string `json:"restoration_generation"`
	}
	if json.Unmarshal(data, &receipt) != nil || receipt.Schema != 1 || receipt.Engine != current.Engine || receipt.Phase != "restored" || receipt.RestorationGeneration != current.Generation {
		return errors.New("restoration receipt is not bound to fresh A authority")
	}
	return nil
}

func TestD10NativeRestoredBindingRejectsRevivedOrForeignAuthority(t *testing.T) {
	oldGeneration, oldReceipt := strings.Repeat("1", 32), strings.Repeat("2", 32)
	newGeneration, newReceipt := strings.Repeat("3", 32), strings.Repeat("4", 32)
	binding := func(generation, receipt string) string {
		return fmt.Sprintf(`{"schema":1,"engine":"sing-box","policy_sha256":"%s","generation":"%s","receipt_id":"%s","phase":"active"}`, strings.Repeat("a", 64), generation, receipt)
	}
	before, after := binding(oldGeneration, oldReceipt), binding(newGeneration, newReceipt)
	receipt := fmt.Sprintf(`{"schema":1,"Engine":"sing-box","Phase":"restored","restoration_generation":"%s"}`, newGeneration)
	for _, tc := range []struct {
		name, after, receipt string
		allowed              bool
	}{
		{"fresh-linked-A", after, receipt, true},
		{"old-generation", binding(oldGeneration, newReceipt), receipt, false},
		{"old-receipt", binding(newGeneration, oldReceipt), receipt, false},
		{"foreign-policy", strings.Replace(after, strings.Repeat("a", 64), strings.Repeat("b", 64), 1), receipt, false},
		{"inactive", strings.Replace(after, "active", "pending", 1), receipt, false},
		{"foreign-engine", strings.Replace(after, "sing-box", "xray", 1), receipt, false},
		{"duplicate-generation", strings.Replace(after, `"generation":`, `"generation":"`+oldGeneration+`","generation":`, 1), receipt, false},
		{"trailing", after + " null", receipt, false},
		{"wrong-restoration-link", after, strings.Replace(receipt, newGeneration, oldGeneration, 1), false},
		{"unfinished-restoration", after, strings.Replace(receipt, "restored", "restoring", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "policy-additions.json"), []byte(tc.receipt), 0600); err != nil {
				t.Fatal(err)
			}
			if err := d10NativeRestoredBinding([]byte(before), []byte(tc.after), root); (err == nil) != tc.allowed {
				t.Fatalf("restoration assertion allowed=%t, want=%t", err == nil, tc.allowed)
			}
		})
	}
}

func d10NativeBackendTopology(t *testing.T, ctx context.Context) (string, func() error) {
	t.Helper()
	const namespace = "rz-d10-backend"
	if out, err := d10NativeCommand(ctx, "ip", "netns", "add", namespace); err != nil {
		clear(out)
		t.Fatal("owned backend namespace creation", d10NativeErrorClass(err))
	}
	var once sync.Once
	var closeErr error
	stop := func() error {
		once.Do(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			out, err := d10NativeCommand(cleanup, "ip", "netns", "delete", namespace)
			if err != nil {
				err = fmt.Errorf("owned namespace deletion: %s: %w", strings.TrimSpace(string(out)), err)
			}
			clear(out)
			closeErr = err
			deleted := err == nil
			links, err := net.Interfaces()
			readable := err == nil
			if err != nil {
				closeErr = errors.Join(closeErr, err)
			}
			survived := false
			for _, link := range links {
				if link.Name == "wan-r" {
					survived = true
					closeErr = errors.Join(closeErr, errors.New("owned backend veth survived namespace removal"))
				}
			}
			if closeErr != nil {
				t.Logf("owned namespace cleanup flags: delete-succeeded=%t interfaces-readable=%t veth-survived=%t", deleted, readable, survived)
				if err := d10NativePrivateReceipt("namespace-cleanup", []string{d10NativeRedact(closeErr.Error())}); err != nil {
					closeErr = errors.Join(closeErr, fmt.Errorf("private namespace cleanup receipt: %w", err))
				}
			}
		})
		return closeErr
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error("owned backend namespace cleanup", d10NativeErrorClass(err))
		}
	})
	commands := [][]string{
		{"link", "add", "wan-r", "type", "veth", "peer", "name", "wan-s", "netns", namespace},
		{"addr", "add", "192.0.2.2/30", "dev", "wan-r"},
		{"link", "set", "wan-r", "addrgenmode", "none"},
		{"link", "set", "wan-r", "up"},
		{"-n", namespace, "link", "set", "lo", "up"},
		{"-n", namespace, "addr", "add", "192.0.2.1/30", "dev", "wan-s"},
		{"-n", namespace, "link", "set", "wan-s", "addrgenmode", "none"},
		{"-n", namespace, "link", "set", "wan-s", "up"},
		{"route", "add", "93.184.216.0/24", "via", "192.0.2.1", "dev", "wan-r", "src", "93.184.216.16"},
		// Production sing-box auto_detect_interface needs a real default route.
		// This peer reaches only the owned backend, with no external uplink.
		{"route", "add", "default", "via", "192.0.2.1", "dev", "wan-r", "src", "93.184.216.16"},
		{"-n", namespace, "route", "add", "93.184.216.16/32", "via", "192.0.2.2"},
		{"-n", namespace, "route", "add", "192.168.1.0/24", "via", "192.0.2.2"},
	}
	for _, address := range []string{"93.184.216.11", "93.184.216.12", "93.184.216.13", "93.184.216.14", "93.184.216.15"} {
		commands = append(commands, []string{"-n", namespace, "addr", "add", address + "/32", "dev", "lo"})
	}
	for _, args := range commands {
		if out, err := d10NativeCommand(ctx, "ip", args...); err != nil {
			clear(out)
			t.Fatal("owned backend veth topology", d10NativeErrorClass(err))
		}
	}
	return namespace, stop
}

// Owned remote endpoint role for the veth/netns topology. Public service/node
// addresses are local only to this backend, never the App/router namespace.
func d10NativeBackend(t *testing.T) {
	root := os.Getenv("RAZVILKA_D10_NATIVE_ROOT")
	namespace, err := os.Readlink("/proc/self/ns/net")
	if os.Geteuid() != 0 || !filepath.IsAbs(root) || err != nil || namespace == os.Getenv("RAZVILKA_D10_ROUTER_NET") || namespace == os.Getenv("RAZVILKA_D10_PARENT_NET") {
		t.Fatal("remote backend requires its distinct owned network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	data, err := os.ReadFile(filepath.Join(root, "backend-ports.json"))
	if err != nil {
		t.Fatal("owned backend port binding", d10NativeErrorClass(err))
	}
	var ports []int
	if json.Unmarshal(data, &ports) != nil || len(ports) != 3 {
		t.Fatal("invalid owned backend port binding")
	}
	clear(data)
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 10443 || port > 10445 || seen[port] {
			t.Fatal("unexpected owned backend port")
		}
		seen[port] = true
	}
	l, err := net.Listen("tcp4", "93.184.216.12:443")
	if err != nil {
		t.Fatal("owned remote HTTPS listener", d10NativeErrorClass(err))
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, _, _ := net.SplitHostPort(r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		switch r.URL.Path {
		case "/cdn-cgi/trace":
			_, _ = fmt.Fprintf(w, "ip=%s\nwarp=off\n", source)
		case "/":
			_, _ = fmt.Fprint(w, source)
		case "/generate_204":
			block := ""
			if source == "93.184.216.13" {
				block = "block-a"
			} else if source == "93.184.216.14" {
				block = "block-b"
			}
			_, err := os.Stat(filepath.Join(root, block))
			if block != "" && err == nil {
				w.WriteHeader(http.StatusForbidden)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	tlsDone := make(chan error, 1)
	go func() { tlsDone <- server.ServeTLS(l, filepath.Join(root, "ca.pem"), filepath.Join(root, "key.pem")) }()
	var servers []*exec.Cmd
	var waits []chan error
	t.Cleanup(func() {
		ok := !t.Failed()
		for i, cmd := range servers {
			_ = cmd.Process.Kill()
			select {
			case <-waits[i]:
			case <-time.After(3 * time.Second):
				t.Error("owned remote VLESS process was not reaped")
				ok = false
			}
			if err := d10NativePrivateLog(filepath.Join(root, fmt.Sprintf("server-%d.json.log", i)), fmt.Sprintf("backend-%02d", i)); err != nil {
				t.Error("owned backend private error receipt", d10NativeErrorClass(err))
				ok = false
			}
		}
		_ = server.Close()
		_ = l.Close()
		select {
		case err := <-tlsDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Error("owned remote TLS shutdown", d10NativeErrorClass(err))
				ok = false
			}
		case <-time.After(3 * time.Second):
			t.Error("owned remote TLS did not join")
			ok = false
		}
		if ok {
			if err := os.WriteFile(filepath.Join(root, "backend-cleanup.complete"), []byte("owned VLESS stopped; HTTPS joined\n"), 0600); err != nil {
				t.Error("owned backend cleanup receipt", d10NativeErrorClass(err))
			}
		}
	})
	for i, port := range ports {
		doc := map[string]any{"log": map[string]any{"loglevel": "warning", "access": "none"},
			"dns": map[string]any{"hosts": map[string]any{"service.example": "93.184.216.12", "www.cloudflare.com": "93.184.216.12", "api.ipify.org": "93.184.216.12"}},
			"inbounds": []any{map[string]any{"listen": "93.184.216.11", "port": port, "protocol": "vless",
				"settings":       map[string]any{"clients": []any{map[string]any{"id": "123e4567-e89b-12d3-a456-426614174000"}}, "decryption": "none"},
				"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": filepath.Join(root, "ca.pem"), "keyFile": filepath.Join(root, "key.pem")}}}}}},
			"outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": fmt.Sprintf("93.184.216.%d", 13+i), "settings": map[string]any{"domainStrategy": "UseIPv4"}}}}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal("owned backend config encode", d10NativeErrorClass(err))
		}
		path := filepath.Join(root, fmt.Sprintf("server-%d.json", i))
		if err := os.WriteFile(path, data, 0600); err != nil {
			clear(data)
			t.Fatal("owned backend config write", d10NativeErrorClass(err))
		}
		clear(data)
		binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
		if out, err := d10NativeCommand(ctx, binary, "run", "-test", "-config", path); err != nil {
			clear(out)
			t.Fatal("real remote VLESS config refused", d10NativeErrorClass(err))
		}
		log, err := os.OpenFile(path+".log", os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("owned backend private log", d10NativeErrorClass(err))
		}
		cmd := exec.Command(binary, "run", "-config", path)
		cmd.Stdout, cmd.Stderr = log, log
		err = cmd.Start()
		_ = log.Close()
		if err != nil {
			t.Fatal("real remote VLESS start", d10NativeErrorClass(err))
		}
		servers = append(servers, cmd)
		done := make(chan error, 1)
		waits = append(waits, done)
		go func() { done <- cmd.Wait() }()
		deadline := time.Now().Add(5 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("93.184.216.11", strconv.Itoa(port)), 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				ready = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ready {
			t.Fatal("real remote VLESS did not become ready")
		}
	}
	if err := os.WriteFile(filepath.Join(root, "backend.ready"), []byte("real TLS and VLESS ready\n"), 0600); err != nil {
		t.Fatal("owned backend readiness receipt", d10NativeErrorClass(err))
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("owned backend stop was not received")
		case <-ticker.C:
			if _, err := os.Stat(filepath.Join(root, "backend.stop")); err == nil {
				return
			}
		}
	}
}
