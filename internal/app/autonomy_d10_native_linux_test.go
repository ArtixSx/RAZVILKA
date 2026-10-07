//go:build linux

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const d10NativeService = "my-independent-site"

// ROOT-only. Each case re-executes in fresh net/mount/PID namespaces, with no
// external interface or default route. Public-format addresses are owned local
// fixtures. The production checker, TLS, OS processes, adapter, Manager and
// rollback verifier are retained. This does not attest physical LAN or HIL.
func TestD10NativeAppManagerRollbackFreshC(t *testing.T) {
	if os.Getenv("RAZVILKA_D10_NATIVE") != "1" {
		t.Skip("ROOT-only: explicit native D10 opt-in and pinned Xray/Sing-box binaries")
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
	for _, scenario := range []string{"sing-box", "failure-exit"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			d10NativeCertificate(t, root)
			hosts := "127.0.0.1 localhost\n93.184.216.12 service.example www.cloudflare.com api.ipify.org\n"
			if err := os.WriteFile(filepath.Join(root, "hosts"), []byte(hosts), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc", "--propagation", "private", exe,
				"-test.run=^TestD10NativeAppManagerRollbackFreshC$", "-test.v", "-test.timeout=3m30s")
			cmd.Env = append(os.Environ(), "RAZVILKA_D10_NATIVE_CHILD="+scenario, "RAZVILKA_D10_NATIVE_ROOT="+root,
				"RAZVILKA_D10_PARENT_NET="+ns["net"], "RAZVILKA_D10_PARENT_MNT="+ns["mnt"], "RAZVILKA_D10_PARENT_PID="+ns["pid"],
				"SSL_CERT_FILE="+filepath.Join(root, "ca.pem"), "SSL_CERT_DIR="+filepath.Join(root, "empty-roots"))
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
	afterStart func(dataplane.ProcessSpec) error
}

func (p *d10NativeProcesses) Start(ctx context.Context, spec dataplane.ProcessSpec) error {
	if err := p.OSProcessController.Start(ctx, spec); err != nil {
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

type d10NativeChecks struct {
	dataplane.NodeChecker
	before  func(context.Context, dataplane.NodeCheckRequest) error
	ids     []string
	results []dataplane.NodeCheckResult
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
	return result, err
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
	for _, dir := range []string{opt, filepath.Join(opt, "bin"), filepath.Join(opt, "etc", "razvilka"), filepath.Join(opt, "var", "lib", "razvilka")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// These bind mounts live only in the fresh private mount namespace.
	for _, mount := range [][2]string{{opt, "/opt"}, {filepath.Join(root, "hosts"), "/etc/hosts"}} {
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
	for _, ip := range []string{"93.184.216.11", "93.184.216.12", "93.184.216.13", "93.184.216.14", "93.184.216.15"} {
		commands = append(commands, []string{"addr", "add", ip + "/32", "dev", "lo"})
	}
	for _, args := range commands {
		if out, err := d10NativeCommand(ctx, "ip", args...); err != nil {
			t.Fatalf("owned fixture setup: %v %s", err, out)
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/br0/disable_ipv6", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Load the tables before the baseline: lazy module/table creation is not a
	// leaked rule. Comparison below still requires every actual rule to restore.
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"filter", "mangle", "nat"} {
			if out, err := d10NativeCommand(ctx, tool, "-t", table, "-S"); err != nil {
				t.Fatalf("fixture firewall read: %v %s", err, out)
			}
		}
	}
	kernelBase, err := d10NativeKernel(ctx)
	if err != nil {
		t.Fatal(err)
	}
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
	var blockA, blockB atomic.Bool
	l, err := net.Listen("tcp4", "93.184.216.12:443")
	if err != nil {
		t.Fatal(err)
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
			if source == "93.184.216.13" && blockA.Load() || source == "93.184.216.14" && blockB.Load() {
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
	var serverWait []chan error
	processes := &d10NativeProcesses{}
	var adapter *dataplane.ProxyTunnelAdapter
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
		for i, cmd := range servers {
			_ = cmd.Process.Kill()
			select {
			case <-serverWait[i]:
			case <-cleanup.Done():
				t.Error("native server was not reaped")
				ok = false
			}
		}
		_ = server.Close()
		_ = l.Close()
		select {
		case err := <-tlsDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("TLS fixture: %v", err)
				ok = false
			}
		case <-cleanup.Done():
			t.Error("TLS fixture did not join")
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
	for i, id := range ids {
		doc := map[string]any{"log": map[string]any{"loglevel": "warning", "access": "none"},
			"dns": map[string]any{"hosts": map[string]any{"service.example": "93.184.216.12", "www.cloudflare.com": "93.184.216.12", "api.ipify.org": "93.184.216.12"}},
			"inbounds": []any{map[string]any{"listen": "93.184.216.11", "port": ports[id], "protocol": "vless",
				"settings":       map[string]any{"clients": []any{map[string]any{"id": "123e4567-e89b-12d3-a456-426614174000"}}, "decryption": "none"},
				"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": filepath.Join(root, "ca.pem"), "keyFile": filepath.Join(root, "key.pem")}}}}}},
			"outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": fmt.Sprintf("93.184.216.%d", 13+i), "settings": map[string]any{"domainStrategy": "UseIPv4"}}}}
		data, _ := json.Marshal(doc)
		path := filepath.Join(root, fmt.Sprintf("server-%d.json", i))
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		clear(data)
		binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
		if out, err := d10NativeCommand(ctx, binary, "run", "-test", "-config", path); err != nil {
			clear(out)
			t.Fatal("real native server config rejected", err)
		}
		log, err := os.OpenFile(path+".log", os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-config", path)
		cmd.Stdout, cmd.Stderr = log, log
		err = cmd.Start()
		_ = log.Close()
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, cmd)
		done := make(chan error, 1)
		serverWait = append(serverWait, done)
		go func() { done <- cmd.Wait() }()
		deadline := time.Now().Add(5 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("93.184.216.11", strconv.Itoa(ports[id])), 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				ready = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ready {
			t.Fatal("real VLESS server not ready")
		}
	}
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
		t.Fatal("first node lacks genuine exact engine/service/paired TLS proof", first.State)
	}
	if first.State != "applied" || selectedRoute(store.Get().AppliedServices[d10NativeService]) != engine+":"+ids[0] {
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
		status, err := a.Dataplane.Status()
		if err != nil || status.Execution == nil || status.Plan == nil || status.Execution.State != "rolled-back" || !status.Execution.RollbackVerified {
			return errors.New("fresh C preceded verified native rollback journal")
		}
		failedB = *status.Execution
		committed, exists, err := a.Dataplane.Committed()
		if err != nil || !exists || !reflect.DeepEqual(committed, planA) || !reflect.DeepEqual(store.Get(), base) {
			return errors.New("fresh C preceded exact A config/committed restoration")
		}
		confirmed, err := adapter.VerifyRollback(c, *status.Plan, filepath.Join(state, "transactions", failedB.PlanID, engine))
		if err != nil || !confirmed {
			return errors.New("independent production VerifyRollback rejected A")
		}
		for name, expected := range filesA {
			actual, err := os.ReadFile(filepath.Join(adapter.StateRoot, name))
			match := err == nil && bytes.Equal(actual, expected)
			clear(actual)
			if !match {
				return errors.New("restored native A files differ")
			}
		}
		kernel, err := d10NativeKernel(c)
		if err != nil || !reflect.DeepEqual(kernel, kernelA) {
			return errors.New("restored native A kernel differs")
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
				blockB.Store(true)
			}
		}
		return nil
	}
	blockA.Store(true)
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
