package dataplane

import (
	"context"
	"errors"
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

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// This consumer model exercises the real manager, opaque component/native
// issuer, staged files, durable leases and rollback. Kernel/process reads are
// explicitly modelled; it provides no native packet or child-Wait evidence.
type firstStartFixture struct {
	stockAdapterFixture
	policyMark                  string
	policyFacts                 []byte
	wan                         string
	running, foreign, ambiguous bool
	ownedRules                  bool
	boot                        string
	nextPID                     int
	identity                    components.NFQWSRuntimeProcessIdentity
	calls                       []string
	afterStop                   func()
	original                    map[string][]byte
}

func newFirstStartFixture(t *testing.T) *firstStartFixture {
	t.Helper()
	backing := os.Getenv("RAZVILKA_FIRST_START_TEST_OPT")
	actual, actualErr := os.Stat("/opt")
	private, privateErr := os.Stat(backing)
	if backing == "" || actualErr != nil || privateErr != nil || !os.SameFile(actual, private) {
		t.Fatal("consumer model requires its isolated bound /opt")
	}
	for _, name := range []string{"etc", "lib", "usr", "var", "bin", "razvilka"} {
		if err := os.RemoveAll(filepath.Join("/opt", name)); err != nil {
			t.Fatal(err)
		}
	}
	f := &firstStartFixture{stockAdapterFixture: newStockAdapterFixtureAt(t, "/opt"), nextPID: 100, boot: "12345678-1234-1234-1234-123456789abc"}
	f.wan = "eth3"
	stock, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	writeStockText(t, f.a.ConfigPath, string(stock))
	info := filepath.Join(f.owner.InfoDir, "nfqws2-keenetic.list")
	writeStockText(t, info, readText(t, info)+"/opt/etc/nfqws2/lua/zapret-antidpi.lua.gz\n")
	writeStockText(t, filepath.Join(filepath.Dir(f.a.ConfigPath), "lua", "zapret-antidpi.lua.gz"), "second installed Lua asset\n")
	runner := nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		if slices.Contains(args, "--dry-run") {
			return f.runner.Run(ctx, name, args...)
		}
		if name == f.a.InitPath && len(args) == 1 {
			switch args[0] {
			case "owned_status":
				if f.running {
					return []byte("service is running"), nil
				}
				return []byte("service is not running"), errors.New("exit1")
			case "restart":
				t.Error("first-start must never call broad stock restart")
				return nil, errors.New("unexpected restart")
			case "owned_start":
				if f.foreign || f.running {
					t.Error("start over an existing process")
					return nil, errors.New("already running")
				}
				f.running = true
				f.ownedRules = true
				writeStockText(t, f.a.ConfigPath+".run", "ISP_INTERFACE=\"eth3\"\nIPV6_ENABLED=0\nTCP_PORTS=443\nUDP_PORTS=\nPOLICY_NAME=\"nfqws\"\nPOLICY_EXCLUDE=0\nPOLICY_MARK=\""+f.policyMark+"\"\nNFQUEUE_NUM=300\n")
				f.nextPID++
				if !f.ambiguous {
					owner, _ := f.a.owner()
					main, err := engineconfig.NFQWSFirstStartEffectiveConfig(readBytes(t, f.a.ConfigPath), owner)
					if err != nil {
						t.Fatal(err)
					}
					argv, err := engineconfig.NFQWSStartupArguments(main, nil)
					if err != nil {
						t.Fatal(err)
					}
					program := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(f.a.InitPath))), "usr", "bin", "nfqws2")
					f.identity = components.NFQWSRuntimeProcessIdentity{BootID: f.boot, Start: strconv.Itoa(f.nextPID), PID: f.nextPID, ParentPID: 1, Group: f.nextPID, Executable: program, ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(program, append([]string{"--daemon", "--pidfile=" + f.a.firstStartPIDPath()}, argv...))}
					if err := os.MkdirAll(filepath.Dir(f.a.firstStartPIDPath()), 0700); err != nil {
						t.Fatal(err)
					}
					writeStockText(t, f.a.firstStartPIDPath(), strconv.Itoa(f.nextPID)+"\n")
				}
				return []byte("Started NFQWS2 service"), nil
			case "owned_stop":
				if f.foreign {
					t.Error("stop touched foreign runtime")
					return nil, errors.New("foreign")
				}
				f.running = false
				f.ownedRules = false
				_ = os.Remove(f.a.firstStartPIDPath())
				_ = os.Remove(f.a.ConfigPath + ".run")
				if f.afterStop != nil {
					f.afterStop()
				}
				return []byte("Stopped"), nil
			}
		}
		if name == f.a.IPTablesSave {
			if f.ownedRules {
				return []byte("-A nfqws_post -p tcp --dports 443 -j NFQUEUE --queue-num 300"), nil
			}
			return nil, nil
		}
		return nil, errors.New("unexpected modeled command")
	})
	f.a.Runner, f.owner.Runner = runner, runner
	f.a.firstStartScopeRead = func(context.Context) ([]byte, string, error) { return f.policyFacts, f.wan, nil }
	f.a.firstStartObservation = func(ctx context.Context, _ bool) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if f.foreign || f.running || f.ownedRules {
			return ErrNFQWSManagedKernelOwner
		}
		return nil
	}
	f.a.firstStartProcessRead = func(pid int) (components.NFQWSRuntimeProcessIdentity, error) {
		if !f.running || pid != f.identity.PID {
			return components.NFQWSRuntimeProcessIdentity{}, os.ErrNotExist
		}
		return f.identity, nil
	}
	f.a.firstStartStopReview = func(_ context.Context, id components.NFQWSRuntimeProcessIdentity) error {
		raw, err := os.ReadFile(f.a.firstStartPIDPath())
		if err != nil || strings.TrimSpace(string(raw)) != strconv.Itoa(id.PID) || f.foreign || id != f.identity {
			return ErrNFQWSManagedProcessUnknown
		}
		return nil
	}
	f.original = map[string][]byte{}
	for _, path := range append(f.a.globalResources(), f.a.InitPath) {
		f.original[path] = readBytes(t, path)
	}
	return f
}

// The real compiler and init use literal /opt assets. Exercise that genuine
// filesystem namespace, never substitute unrelated temporary Lua paths into
// a successful native-review claim. No packet/process effects are performed.
func firstStartNamespace(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux private mount namespace for literal stock /opt")
		return true
	}
	if backing := os.Getenv("RAZVILKA_FIRST_START_TEST_OPT"); backing != "" {
		if err := exec.Command("mount", "--bind", backing, "/opt").Run(); err != nil {
			t.Fatal("mount isolated stock prefix", err)
		}
		return false
	}
	if _, err := os.Stat("/opt"); err != nil {
		t.Skip("namespace fixture needs existing /opt mountpoint")
		return true
	}
	backing := filepath.Join(t.TempDir(), "opt")
	if err := os.Mkdir(backing, 0700); err != nil {
		t.Fatal(err)
	}
	args := []string{"--mount", "--propagation", "private"}
	if os.Geteuid() != 0 {
		args = append([]string{"--user", "--map-root-user"}, args...)
	}
	args = append(args, os.Args[0], "-test.run=^"+strings.Split(t.Name(), "/")[0]+"$", "-test.count=1", "-test.v")
	cmd := exec.Command("unshare", args...)
	cmd.Env = append(os.Environ(), "RAZVILKA_FIRST_START_TEST_OPT="+backing)
	output, err := cmd.CombinedOutput()
	if err != nil && (strings.Contains(string(output), "Operation not permitted") || strings.Contains(string(output), "Permission denied")) {
		t.Skip("user/mount namespace unavailable; required sudo namespace run: " + string(output))
		return true
	}
	if err != nil {
		t.Fatalf("isolated consumer: %v\n%s", err, output)
	}
	t.Log(string(output))
	return true
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func firstStartContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func (f *firstStartFixture) apply(t *testing.T) {
	t.Helper()
	if result, err := f.m.Apply(firstStartContext(t), f.plan, nil); err != nil {
		t.Fatal(result, err)
	}
}
func (f *firstStartFixture) assertOriginal(t *testing.T) {
	t.Helper()
	for path, before := range f.original {
		if !reflect.DeepEqual(readBytes(t, path), before) {
			t.Error("original resource differs", filepath.Base(path))
		}
	}
}

func (f *firstStartFixture) assertStopped(t *testing.T) {
	t.Helper()
	lease, err := f.a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Phase != nfqws2FirstStopped || f.running || f.ownedRules {
		t.Fatal("not settled stopped", err)
	}
	if _, err := f.a.verifyOwnedLists(false); err != nil {
		t.Fatal(err)
	}
	if _, err := engineconfig.NFQWSFirstStartInitOwner(readBytes(t, f.a.InitPath)); err != nil {
		t.Fatal("Stop restored an active stock init", err)
	}
	if !strings.Contains(readText(t, f.a.ConfigPath), engineconfig.NFQWSFirstStartFormat) {
		t.Fatal("closed profile was relinquished")
	}
}

func firstStartRuntimeAction(call string) bool {
	for _, action := range []string{" start", " stop", " restart", " owned_start", " owned_stop"} {
		if strings.HasSuffix(call, action) {
			return true
		}
	}
	return false
}

func TestNFQWS2FirstStartApplySecondPlanThenStop(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	first, err := f.a.readLease()
	if err != nil || first == nil || first.FirstStart == nil || first.FirstStart.Phase != nfqws2FirstRunning {
		t.Fatal("missing running intent", err)
	}
	if len(f.calls) == 0 || strings.HasSuffix(f.calls[0], " status") {
		t.Fatal("first-start status ran before data/native preflight", f.calls)
	}
	f.plan.PlanID = "dp-first-second"
	f.plan.Digest = strings.Repeat("b", 64)
	f.plan.Routes[0].Domains = []string{"second.example"}
	f.apply(t)
	second, err := f.a.readLease()
	if err != nil || second.FirstStart.Process.PID == first.FirstStart.Process.PID {
		t.Fatal("second process receipt stale", err)
	}
	if !strings.Contains(readText(t, f.a.ConfigPath), "--hostlist-domains=second.example") || strings.Contains(readText(t, f.a.ConfigPath), "--hostlist-domains=selected.example") {
		t.Fatal("actual second plan not consumed")
	}
	if err := f.a.Deactivate(firstStartContext(t)); err != nil {
		t.Fatal(err)
	}
	if f.running {
		t.Fatal("Stop left daemon running")
	}
	f.assertStopped(t)
}

func TestNFQWS2FirstStartFailedSecondApplyRestoresPriorThenStop(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	prior := readText(t, f.a.ConfigPath)
	f.plan.PlanID = "dp-first-failed"
	f.plan.Digest = strings.Repeat("b", 64)
	f.plan.Routes[0].Domains = []string{"bad.example"}
	f.a.HealthProbe = func(context.Context, string) error { return errors.New("site unreachable") }
	result, err := f.m.Apply(firstStartContext(t), f.plan, nil)
	if err == nil || result.State != "rolled-back" {
		t.Fatal("failed apply did not verify rollback", result, err)
	}
	if !f.running || readText(t, f.a.ConfigPath) != prior {
		t.Fatal("prior closed runtime not restored")
	}
	lease, err := f.a.readLease()
	if err != nil || lease == nil || lease.FirstStart.Process.PID != f.identity.PID {
		t.Fatal("restored process not recaptured", err)
	}
	if err := f.a.Deactivate(firstStartContext(t)); err != nil {
		t.Fatal(err)
	}
	f.assertStopped(t)
}

func TestNFQWS2FirstStartForeignBeforeStartNeverStops(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.a.activationLeaseReady = func() { f.foreign = true }
	if _, err := f.m.Apply(firstStartContext(t), f.plan, nil); err == nil {
		t.Fatal("foreign runtime accepted")
	}
	for _, call := range f.calls {
		if firstStartRuntimeAction(call) {
			t.Fatal("foreign runtime touched", f.calls)
		}
	}
	f.assertOriginal(t)
}

func TestNFQWS2FirstStartAmbiguousLaunchRetainsFence(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.ambiguous = true
	if _, err := f.m.Apply(firstStartContext(t), f.plan, nil); err == nil {
		t.Fatal("ambiguous start succeeded")
	}
	for _, call := range f.calls {
		if strings.HasSuffix(call, " owned_stop") {
			t.Fatal("unknown process killed")
		}
	}
	lease, err := f.a.readLease()
	if err != nil || lease == nil || lease.FirstStart.Phase != nfqws2FirstStarting || lease.FirstStart.Process != nil {
		t.Fatal("unknown start intent lost", err)
	}
	if err := f.a.Deactivate(firstStartContext(t)); err == nil {
		t.Fatal("unknown process cleanup accepted")
	}
}

func TestNFQWS2FirstStartStoppedCleanupRetryDoesNotNeedPID(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	// A foreign edit during stop prevents its later CAS replacement. The
	// terminal stopped receipt must survive and join a subsequent retry.
	originalInit := readText(t, f.a.InitPath)
	f.afterStop = func() { writeStockText(t, f.a.InitPath, originalInit+"# foreign drift\n") }
	if err := f.a.Deactivate(firstStartContext(t)); err == nil {
		t.Fatal("drift during cleanup overwritten")
	}
	lease, err := f.a.readLease()
	if err != nil || lease == nil || lease.FirstStart.Phase != nfqws2FirstStopped {
		t.Fatal("stopped outcome not retained", err)
	}
	stops := 0
	for _, call := range f.calls {
		if strings.HasSuffix(call, " owned_stop") {
			stops++
		}
	}
	f.afterStop = nil
	writeStockText(t, f.a.InitPath, originalInit)
	if err := f.a.Deactivate(firstStartContext(t)); err != nil {
		t.Fatal("stopped cleanup could not retry", err)
	}
	after := 0
	for _, call := range f.calls {
		if strings.HasSuffix(call, " owned_stop") {
			after++
		}
	}
	if stops != after {
		t.Fatal("retry killed an absent PID")
	}
	f.assertStopped(t)
}

func TestNFQWS2FirstStartRefusesUnknownShellBeforeStatus(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"init", "block", "run", "policy", "missing-field"} {
		t.Run(which, func(t *testing.T) {
			f := newFirstStartFixture(t)
			switch which {
			case "init":
				writeStockText(t, f.a.InitPath, readText(t, f.a.InitPath)+"touch /tmp/unknown\n")
			case "block":
				writeStockText(t, f.a.ConfigPath, readText(t, f.a.ConfigPath)+managedBegin+"\ntouch /tmp/unknown\n"+managedEnd+"\n")
			case "run":
				writeStockText(t, f.a.ConfigPath+".run", "touch /tmp/unknown\n")
			case "policy":
				writeStockText(t, f.a.ConfigPath, strings.Replace(readText(t, f.a.ConfigPath), `POLICY_NAME="nfqws"`, `POLICY_NAME='"; touch /tmp/unknown; #'`, 1))
			case "missing-field":
				writeStockText(t, f.a.ConfigPath, strings.Replace(readText(t, f.a.ConfigPath), `POLICY_NAME="nfqws"`, `UNKNOWN=nfqws`, 1))
			}
			if _, err := f.m.Apply(firstStartContext(t), f.plan, nil); err == nil {
				t.Fatal("unsafe shell accepted")
			}
			for _, call := range f.calls {
				if strings.HasPrefix(call, f.a.InitPath+" ") {
					t.Fatal("unsafe shell reached init", f.calls)
				}
			}
		})
	}
}

func TestNFQWS2FirstStartOriginalAssetsRetainedUntilExecution(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"binary", "lua"} {
		t.Run(which, func(t *testing.T) {
			f := newFirstStartFixture(t)
			path := "/opt/usr/bin/nfqws2"
			if which == "lua" {
				path = "/opt/etc/nfqws2/lua/zapret-lib.lua.gz"
			}
			f.a.activationLeaseReady = func() { writeStockText(t, path, "changed after original native validation\n") }
			if _, err := f.m.Apply(firstStartContext(t), f.plan, nil); err == nil {
				t.Fatal("changed original package accepted")
			}
			for _, call := range f.calls {
				if firstStartRuntimeAction(call) {
					t.Fatal("changed package caused runtime action", f.calls)
				}
			}
			if f.a.firstStartReview != nil {
				t.Fatal("original review leaked")
			}
			f.assertOriginal(t)
		})
	}
}

func TestNFQWS2FirstStartOtherAdapterRefusalClosesOriginalReview(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"validate", "canary"} {
		t.Run(which, func(t *testing.T) {
			f := newFirstStartFixture(t)
			other := &fakeAdapter{id: "wireguard", failAt: "validate"}
			var adapter Adapter = other
			if which == "canary" {
				other.failAt = ""
				adapter = &canaryFakeAdapter{fakeAdapter: other, fail: true}
			}
			if err := f.m.Register(adapter); err != nil {
				t.Fatal(err)
			}
			f.plan.Adapters = append(f.plan.Adapters, "wireguard")
			if _, err := f.m.Apply(firstStartContext(t), f.plan, nil); err == nil {
				t.Fatal("other adapter refusal ignored")
			}
			if f.a.firstStartReview != nil {
				t.Fatal("original review retained after refusal")
			}
			review, err := f.owner.ReviewStockNFQWSNative(firstStartContext(t), []string{"--user=nobody", "--qnum=300", "--filter-tcp=443"})
			if err != nil {
				t.Fatal("component writer was not released", err)
			}
			if err := review.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNFQWS2FirstStartRejectsMixedAndScopedActualPlan(t *testing.T) {
	config, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	a := NewNFQWS2Adapter()
	if err := a.bindStateRoot(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, route := range []Route{{Resolved: "nfqws2", Domains: []string{"domain.example"}, CIDRs: []string{"192.0.2.0/24"}}, {Resolved: "nfqws2", CIDRs: []string{"192.0.2.0/24"}}, {Resolved: "nfqws2", Domains: []string{"domain.example"}, Sources: []string{"192.0.2.1/32"}}} {
		if _, err := a.firstStartConfig(Plan{Routes: []Route{route}}, config); err == nil {
			t.Fatal("unrepresented route scope accepted", route)
		}
	}
}

func TestNFQWS2FirstStartExitWaitKeepsExactIdentity(t *testing.T) {
	a := NewNFQWS2Adapter()
	receipt := components.NFQWSRuntimeProcessIdentity{PID: 33, Start: "15"}
	reads := 0
	a.firstStartProcessRead = func(int) (components.NFQWSRuntimeProcessIdentity, error) {
		reads++
		if reads < 3 {
			return receipt, nil
		}
		return components.NFQWSRuntimeProcessIdentity{}, os.ErrNotExist
	}
	if err := a.waitFirstStartExit(firstStartContext(t), receipt); err != nil || reads < 3 {
		t.Fatal("normal asynchronous exit refused", err, reads)
	}
	a.firstStartProcessRead = func(int) (components.NFQWSRuntimeProcessIdentity, error) {
		other := receipt
		other.Start = "16"
		return other, nil
	}
	if err := a.waitFirstStartExit(firstStartContext(t), receipt); err == nil {
		t.Fatal("PID reuse treated as joined exit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.firstStartProcessRead = func(int) (components.NFQWSRuntimeProcessIdentity, error) { return receipt, nil }
	if err := a.waitFirstStartExit(ctx, receipt); !errors.Is(err, context.Canceled) {
		t.Fatal("exit wait ignored cancellation", err)
	}
}
