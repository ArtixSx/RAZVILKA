package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

type stockAdapterRunner struct {
	calls     []string
	args      []string
	onNative  func()
	nativeErr error
	deadline  time.Duration
}

func (r *stockAdapterRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if slices.Contains(args, "--dry-run") {
		r.args = slices.Clone(args)
		if deadline, ok := ctx.Deadline(); ok {
			r.deadline = time.Until(deadline)
		}
		if r.onNative != nil {
			r.onNative()
		}
		return []byte("command line parameters verified"), r.nativeErr
	}
	if len(args) > 0 && args[0] == "status" {
		return []byte("Service NFQWS2 is running"), nil
	}
	if strings.Contains(name, "iptables-save") {
		return []byte("-A nfqws_post -j NFQUEUE --queue-num 300"), nil
	}
	return []byte("ok"), nil
}

type stockAdapterFixture struct {
	m      *Manager
	a      *NFQWS2Adapter
	owner  *components.Manager
	runner *stockAdapterRunner
	plan   Plan
}

func newStockAdapterFixture(t *testing.T) stockAdapterFixture {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "opt")
	return newStockAdapterFixtureAt(t, prefix)
}

func newStockAdapterFixtureAt(t *testing.T, prefix string) stockAdapterFixture {
	t.Helper()
	base := filepath.Join(prefix, "etc", "nfqws2")
	runner := &stockAdapterRunner{}
	a := &NFQWS2Adapter{ConfigPath: filepath.Join(base, "nfqws2.conf"), InitPath: filepath.Join(prefix, "etc", "init.d", "S51nfqws2"), UserListPath: filepath.Join(base, "lists", "user.list"), IPSetListPath: filepath.Join(base, "lists", "ipset.list"), Runner: runner, HealthProbe: func(context.Context, string) error { return nil }}
	a.IPTablesSave = filepath.Join(prefix, "bin", "iptables-save")
	m := New(filepath.Join(prefix, "razvilka", "dataplane"))
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	owner := components.New()
	owner.InitDir = filepath.Dir(a.InitPath)
	owner.InfoDir = filepath.Join(prefix, "lib", "opkg", "info")
	owner.StateDir = filepath.Join(prefix, "razvilka", "components")
	owner.Runner = runner
	if err := m.ConfigureNFQWSStockNative(owner); err != nil {
		t.Fatal(err)
	}
	init, err := os.ReadFile(filepath.Join("..", "components", "testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	lists := a.ownedListPaths()
	config := "USER=nobody\nNFQUEUE_NUM=300\nISP_INTERFACE=eth3\nIPV6_ENABLED=0\nLOG_LEVEL=0\nNFQWS_BASE_ARGS=\"--lua-init=@" + filepath.ToSlash(filepath.Join(base, "lua", "zapret-lib.lua")) + " --fastpath-workaround=0\"\nNFQWS_ARGS=\"--filter-tcp=443 --payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld\"\nNFQWS_EXTRA_ARGS=\"--hostlist=" + filepath.ToSlash(lists[0]) + " --hostlist-exclude=" + filepath.ToSlash(lists[2]) + "\"\nNFQWS_ARGS_UDP=\"\"\nNFQWS_ARGS_QUIC=\"\"\nNFQWS_ARGS_IPSET=\"\"\nNFQWS_ARGS_CUSTOM=\"\"\n"
	files := map[string]string{
		a.IPTablesSave: "#!/bin/sh\n",
		a.ConfigPath:   config, a.InitPath: string(init), lists[0]: "manual.example\n", lists[1]: "", lists[2]: "excluded.example\n", lists[3]: "",
		filepath.Join(owner.InfoDir, "nfqws2-keenetic.control"):  "Package: nfqws2-keenetic\nVersion: 1.3.1\n",
		filepath.Join(owner.InfoDir, "nfqws2-keenetic.list"):     "/opt/etc/init.d/S51nfqws2\n/opt/etc/nfqws2/nfqws2.conf\n/opt/tmp/nfqws2_binary/nfqws2-aarch64\n/opt/etc/nfqws2/lua/zapret-lib.lua.gz\n",
		filepath.Join(owner.InfoDir, "nfqws2-keenetic.postinst"): `BINFILE="/opt/usr/bin/nfqws2"` + "\n" + `cp -f "/opt/tmp/nfqws2_binary/nfqws2-$ARCH" "$BINFILE"` + "\n",
		filepath.Join(prefix, "usr", "bin", "nfqws2"):            "synthetic executable bytes\n",
		filepath.Join(base, "lua", "zapret-lib.lua.gz"):          "synthetic compressed Lua\n",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	plan := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-stock-native", Digest: strings.Repeat("a", 64), Ready: true, Adapters: []string{"nfqws2"}, Routes: []Route{{ServiceID: "selected", ServiceName: "Selected", Resolved: "nfqws2", Domains: []string{"selected.example"}, ProbeURL: "https://selected.example"}}, SiteExclusions: &SiteExclusions{Domains: []string{"bank.example"}}}
	return stockAdapterFixture{m: m, a: a, owner: owner, runner: runner, plan: plan}
}

func (f stockAdapterFixture) assertWriterReleased(t *testing.T) {
	t.Helper()
	review, err := f.owner.ReviewStockNFQWSNative(context.Background(), []string{"--user=nobody", "--qnum=300", "--filter-tcp=443"})
	if err != nil {
		t.Fatal("original component writer not released", err)
	}
	if err := review.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNFQWS2StockNativeApplyChecksStagedArgumentsBeforeActivation(t *testing.T) {
	f := newStockAdapterFixture(t)
	before := readText(t, f.a.ConfigPath)
	f.runner.onNative = func() {
		if got := readText(t, f.a.ConfigPath); got != before {
			t.Error("native review happened after config install")
		}
	}
	result, err := f.m.Apply(context.Background(), f.plan, nil)
	if err != nil {
		t.Fatal(result, err)
	}
	native, restart := -1, -1
	for i, call := range f.runner.calls {
		if strings.Contains(call, " --dry-run ") {
			native = i
		}
		if strings.HasSuffix(call, " restart") {
			restart = i
		}
	}
	if native < 0 || restart <= native {
		t.Fatal("native check must precede restart", f.runner.calls)
	}
	if f.runner.deadline <= 0 || f.runner.deadline > 10*time.Second {
		t.Fatal("native check lacks bounded timeout", f.runner.deadline)
	}
	if !slices.Equal(f.runner.args[:2], []string{"--dry-run", "--intercept=0"}) {
		t.Fatal(f.runner.args)
	}
	var staged string
	for _, arg := range f.runner.args {
		if strings.HasPrefix(arg, "--hostlist=") {
			staged = strings.TrimPrefix(arg, "--hostlist=")
		}
	}
	if staged == "" || filepath.Clean(staged) == f.a.UserListPath || !strings.Contains(readText(t, staged), "selected.example") {
		t.Fatal("native check did not consume selected staged list", f.runner.args)
	}
	if !strings.Contains(strings.Join(f.runner.args, " "), "--hostlist-domains=bank.example") {
		t.Fatal("missing policy exclusions", f.runner.args)
	}
	f.assertWriterReleased(t)
}

func TestNFQWS2StockNativeApplyRefusesBeforeActivationAndReleasesWriter(t *testing.T) {
	for _, which := range []string{"bad-argv", "native-refused", "stage-changed", "live-changed", "runtime-overlay", "runtime-changed", "policy-changed", "foreign-init"} {
		t.Run(which, func(t *testing.T) {
			f := newStockAdapterFixture(t)
			ctx := context.Background()
			switch which {
			case "bad-argv":
				writeStockText(t, f.a.ConfigPath, readText(t, f.a.ConfigPath)+"FOREIGN=\"$(touch /tmp/foreign)\"\n")
			case "native-refused":
				f.runner.nativeErr = errors.New("native rejected unknown parameter")
			case "stage-changed":
				f.runner.onNative = func() {
					for _, arg := range f.runner.args {
						if strings.HasPrefix(arg, "--hostlist=") {
							writeStockText(t, strings.TrimPrefix(arg, "--hostlist="), "foreign.example\n")
						}
					}
				}
			case "live-changed":
				f.runner.onNative = func() { writeStockText(t, f.a.ConfigPath, "FOREIGN=changed\n") }
			case "runtime-overlay":
				writeStockText(t, f.a.ConfigPath+".run", "NFQUEUE_NUM=999\n")
			case "runtime-changed":
				f.runner.onNative = func() { writeStockText(t, f.a.ConfigPath+".run", "NFQUEUE_NUM=999\n") }
			case "policy-changed":
				current := true
				ctx = WithReviewGuard(ctx, func(context.Context) error {
					if !current {
						return ErrReviewChanged
					}
					return nil
				})
				f.runner.onNative = func() { current = false }
			case "foreign-init":
				writeStockText(t, f.a.InitPath, "#!/bin/sh\n# foreign replacement\n")
			}
			before := readText(t, f.a.UserListPath)
			if _, err := f.m.Apply(ctx, f.plan, nil); err == nil {
				t.Fatal("unsafe native validation succeeded")
			}
			for _, call := range f.runner.calls {
				if strings.HasSuffix(call, " restart") || strings.HasSuffix(call, " stop") {
					t.Fatal("validation refusal changed service state", f.runner.calls)
				}
			}
			if readText(t, f.a.UserListPath) != before {
				t.Fatal("validation refusal installed selected lists")
			}
			if (which == "bad-argv" || which == "runtime-overlay" || which == "foreign-init") && len(f.runner.args) != 0 {
				t.Fatal("unreviewed command reached native runner")
			}
			if which == "foreign-init" {
				init, err := os.ReadFile(filepath.Join("..", "components", "testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
				if err != nil {
					t.Fatal(err)
				}
				writeStockText(t, f.a.InitPath, string(init))
			}
			f.assertWriterReleased(t)
		})
	}
}

func writeStockText(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
}
