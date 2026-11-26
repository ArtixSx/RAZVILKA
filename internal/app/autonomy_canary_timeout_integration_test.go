package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// Only the pre-activation canary is native here. Host availability and the
// surrounding adapter phases use the existing App transaction model; this
// proves neither live Xray forwarding nor router/LAN acceptance.
type appCanaryTimeoutAdapter struct {
	proxy *dataplane.ProxyTunnelAdapter
	model *nodeApplyAdapter
	app   *App
	first error
}

func (*appCanaryTimeoutAdapter) ID() string { return "xray" }
func (m *appCanaryTimeoutAdapter) Snapshot(c context.Context, p dataplane.Plan, root string) error {
	return m.model.Snapshot(c, p, root)
}
func (m *appCanaryTimeoutAdapter) Stage(c context.Context, p dataplane.Plan, root string) error {
	if err := m.model.Stage(c, p, root); err != nil {
		return err
	}
	for _, route := range p.Routes {
		if !strings.HasPrefix(route.Resolved, "xray:node-") {
			continue
		}
		return m.app.Nodes.WithSecret(c, strings.TrimPrefix(route.Resolved, "xray:"), func(raw []byte) error {
			profile, err := providerprofile.VLESSProfileFromJSON(raw)
			if err != nil {
				return err
			}
			compiled, _, err := providerprofile.CompileXrayConfig(profile)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, "engine.staged.json"), compiled, 0600)
		})
	}
	return errors.New("test plan lacks an exact Xray candidate")
}
func (m *appCanaryTimeoutAdapter) Validate(c context.Context, p dataplane.Plan, root string) error {
	return m.model.Validate(c, p, root)
}
func (m *appCanaryTimeoutAdapter) Canary(c context.Context, p dataplane.RoutePlan, root string) error {
	if err := m.model.phase("canary"); err != nil {
		return err
	}
	err := m.proxy.Canary(c, p, root) // Actual producer; no constructed timeout/receipt.
	if m.first == nil {
		m.first = err
	}
	return err
}
func (m *appCanaryTimeoutAdapter) Activate(c context.Context, p dataplane.Plan, root string) error {
	return m.model.Activate(c, p, root)
}
func (m *appCanaryTimeoutAdapter) Health(c context.Context, p dataplane.Plan, root string) error {
	return m.model.Health(c, p, root)
}
func (m *appCanaryTimeoutAdapter) Commit(c context.Context, p dataplane.Plan, root string) error {
	return m.model.Commit(c, p, root)
}
func (m *appCanaryTimeoutAdapter) Rollback(c context.Context, p dataplane.Plan, root string) error {
	return m.model.Rollback(c, p, root)
}

type appUnjoinedCanaryController struct {
	running       bool
	starts, stops int
}

func (p *appUnjoinedCanaryController) Start(context.Context, dataplane.ProcessSpec) error {
	p.running = true
	p.starts++
	return nil
}
func (p *appUnjoinedCanaryController) Stop(context.Context, dataplane.ProcessSpec) error {
	p.running = false
	p.stops++
	return nil
}
func (p *appUnjoinedCanaryController) Running(dataplane.ProcessSpec) bool { return p.running }

type appOriginalCanaryController struct {
	dataplane.OSProcessController
	specs    []dataplane.ProcessSpec
	pids     []int
	children []*dataplane.OriginalProcess
}

func (p *appOriginalCanaryController) StartOriginal(c context.Context, spec dataplane.ProcessSpec, endpoint string) (*dataplane.OriginalProcess, error) {
	child, err := p.OSProcessController.StartOriginal(c, spec, endpoint)
	if err != nil {
		return nil, err
	}
	p.children = append(p.children, child)
	p.specs = append(p.specs, spec)
	raw, err := os.ReadFile(spec.PIDPath)
	if err == nil {
		var pid int
		pid, err = strconv.Atoi(strings.TrimSpace(string(raw)))
		if err == nil && pid > 1 && string(raw) == strconv.Itoa(pid)+"\n" {
			p.pids = append(p.pids, pid)
		} else {
			err = errors.New("original test child PID metadata is not canonical")
		}
	}
	return child, err
}

func appCanaryTimeoutFixture(t *testing.T, controller dataplane.ProcessController) (*App, []string, *appCanaryTimeoutAdapter) {
	t.Helper()
	a, old, _ := autonomousIntegrationFixture(t)
	for i := range a.Catalog.Services {
		if a.Catalog.Services[i].ID == "my-independent-site" {
			a.Catalog.Services[i].Category = "Diagnostic"
			a.Catalog.Services[i].Strategy = []string{"xray"}
		}
	}
	for _, id := range old {
		if _, err := a.Nodes.SetDisabled(context.Background(), id, true, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	uri := strings.Replace(autonomyXHTTPURI, "174001", "174002", 1)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, autonomyXHTTPURI+"\n"+uri, time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, node := range snapshot.Nodes {
		if !node.Disabled && node.Transport == "xhttp" {
			ids = append(ids, node.ID)
		}
	}
	slices.Sort(ids)
	if len(ids) != 2 {
		t.Fatal("fixture requires two distinct AUTO XHTTP peers")
	}
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.PreferredRoutes = []string{"xray"}
	s := a.autonomy.doc.Services["my-independent-site"]
	for _, service := range a.Catalog.Services {
		if service.ID == s.ID {
			s.Definition = autonomyDefinition(service)
		}
	}
	a.autonomy.doc.Services[s.ID] = s
	err = a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	a.nodeReviews.options = func() []routecatalog.Option {
		options := []routecatalog.Option{{ID: "direct", Installed: true, Selectable: true}, {ID: "sing-box", Installed: true, Selectable: true}, {ID: "xray", Installed: true, Configured: true, Selectable: true}}
		for _, id := range ids {
			options = append(options, routecatalog.Option{ID: "xray:" + id, Installed: true, Configured: true, Selectable: true, Services: []string{"my-independent-site"}})
		}
		return options
	}
	a.NodeHistoryWriteGuard = func(c context.Context, _ int) error { return c.Err() }
	a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Fatal("AUTO XHTTP candidate reached the Sing-box checker")
		return dataplane.NodeCheckResult{}, dataplane.ErrExactNodeUnsupported
	})
	proxy, err := dataplane.NewProxyTunnelAdapter("xray", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proxy.Processes, proxy.EngineBin, proxy.Timeout = controller, "xray", 5*time.Second
	proxy.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	proxy.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error { return context.DeadlineExceeded }
	proxy.SOCKSProbe = func(context.Context, string) error { return nil }
	adapter := &appCanaryTimeoutAdapter{proxy: proxy, model: &nodeApplyAdapter{}, app: a}
	if err := a.Dataplane.Register(adapter); err != nil {
		t.Fatal(err)
	}
	return a, ids, adapter
}

func appCanaryInconclusive(req dataplane.NodeCheckRequest) dataplane.NodeCheckResult {
	r := d10Result(req, "xray", true)
	r.Available, r.Verdict, r.ErrorCode = false, evidence.VerdictInconclusive, ""
	r.Evidence = evidence.ProbeEvidence{}
	return r
}

func TestAutonomyUnjoinedCanaryTimeoutCannotContinue(t *testing.T) {
	controller := &appUnjoinedCanaryController{}
	a, ids, adapter := appCanaryTimeoutFixture(t, controller)
	probes := 0
	adapter.proxy.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error {
		probes++
		return context.DeadlineExceeded
	}
	before := a.Store.Get()
	var checked []string
	a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "xray", true), nil
	})}
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if adapter.first == nil || probes != 1 || controller.starts != 1 || controller.stops != 1 || controller.running || r.State == "applied" || r.Search == nil || !r.Search.Halted || !reflect.DeepEqual(checked, ids[:1]) || !reflect.DeepEqual(before, a.Store.Get()) || len(r.CandidateFailures) != 0 {
		t.Fatal("ordinary fake Stop/Running(false) minted continuation authority", r, checked, adapter.model.calls)
	}
}

func TestAutonomyNativeCanaryTimeoutContinuesOnlyAfterOriginalChildJoin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actual original child and listener ownership require Linux procfs")
	}
	binary := buildAppCanaryChild(t)
	controller := &appOriginalCanaryController{}
	t.Cleanup(func() {
		for _, child := range controller.children {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = child.StopAndJoin(cleanup)
			cancel()
		}
	})
	a, ids, adapter := appCanaryTimeoutFixture(t, controller)
	adapter.proxy.EngineBin = binary
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	adapter.proxy.SOCKSPort = port - 1000 // Canary uses SOCKSPort + 1000.
	adapter.proxy.SOCKSProbe = func(c context.Context, endpoint string) error {
		conn, err := (&net.Dialer{}).DialContext(c, "tcp4", endpoint)
		if err == nil {
			conn.Close()
		}
		return err
	}
	endpoint := ""
	adapter.proxy.ServiceIPProbe = func(_ context.Context, _ string, address string, _ netip.Addr) error {
		endpoint = address
		return context.DeadlineExceeded
	}
	before := a.Store.Get()
	nodesBefore, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var checked []string
	a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		if len(checked) == 1 {
			return d10Result(req, "xray", true), nil
		}
		if len(checked) != 2 || req.NodeID != ids[1] || endpoint == "" || len(controller.pids) != 1 || adapter.first == nil {
			t.Fatal("next peer was not checked afresh after an actual canary", checked)
		}
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(controller.pids[0]))); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("next fresh check preceded original Cmd.Wait/reap", err)
		}
		listener, err := net.Listen("tcp4", endpoint)
		if err != nil {
			t.Fatal("next check preceded original listener absence", err)
		}
		listener.Close()
		if _, err := os.Stat(controller.specs[0].PIDPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("next check preceded protected child metadata settlement", err)
		}
		status, err := a.Dataplane.Status()
		if err != nil || status.Execution == nil || status.Execution.State != "canary-failed" {
			t.Fatal("next check preceded real Manager failure publication", err)
		}
		return appCanaryInconclusive(req), nil
	})}
	a.autonomyRound(context.Background(), time.Now())
	r := autonomyTestState(a)
	if !reflect.DeepEqual(checked, ids) || r.Search == nil || r.Search.Halted || r.Search.Cursor != 1 || r.State != "unconfirmed" || len(r.Switches) != 1 || len(r.CandidateFailures) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		status, statusErr := a.Dataplane.Status()
		executionErr := ""
		if status.Execution != nil {
			executionErr = status.Execution.Error
		}
		t.Fatalf("joined native canary continuation refused: first=%v children=%d endpoint_seen=%t status_error=%v execution_error=%s runtime=%+v checked=%v phases=%v", adapter.first, len(controller.children), endpoint != "", statusErr, executionErr, r, checked, adapter.model.calls)
	}
	if !reflect.DeepEqual(adapter.model.calls, []string{"snapshot", "stage", "validate", "canary"}) {
		t.Fatal("canary timeout reached activation, health or commit", adapter.model.calls)
	}
	nodesAfter, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || !reflect.DeepEqual(nodesBefore.Sources, nodesAfter.Sources) {
		t.Fatal("isolated canary timeout changed source consent", err)
	}
	for _, node := range nodesAfter.Nodes {
		if node.ID == ids[0] && (node.Disabled || node.Health.Verdict != "PASS" || node.Health.ErrorCode != "") {
			t.Fatal("isolated canary timeout became a negative node observation", node.ID, node.Health.Verdict)
		}
	}
	d10Reopen(t, a)
	if r := autonomyTestState(a); r.Search.Halted || len(r.CandidateFailures) != 0 || r.Search.Cursor != 1 {
		t.Fatal("restart lost consumed cursor or acquired a node penalty", r)
	}
}

func buildAppCanaryChild(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := `package main
import("encoding/json";"net";"os";"os/signal";"strconv";"syscall")
func main(){
 var path string
 for i:=1;i+1<len(os.Args);i++{if os.Args[i]=="-config"{path=os.Args[i+1]}}
 raw,e:=os.ReadFile(path);if e!=nil{os.Exit(2)}
 var c struct{Inbounds []struct{Listen string;Port int}}
 if json.Unmarshal(raw,&c)!=nil||len(c.Inbounds)!=1||c.Inbounds[0].Listen!="127.0.0.1"{os.Exit(3)}
 l,e:=net.Listen("tcp4",net.JoinHostPort(c.Inbounds[0].Listen,strconv.Itoa(c.Inbounds[0].Port)));if e!=nil{os.Exit(4)}
 stop:=make(chan os.Signal,1);signal.Notify(stop,os.Interrupt,syscall.SIGTERM)
 go func(){for{c,e:=l.Accept();if e!=nil{return};c.Close()}}()
 <-stop;l.Close()
}
`
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "xray")
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.Command(goTool, "build", "-o", binary, path)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build isolated loopback child: %v %s", err, output)
	}
	return binary
}
