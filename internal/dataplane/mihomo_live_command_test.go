package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestMihomoLiveCommandNativeHelper(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_COMMAND_HELPER") == "1" {
		os.Exit(0)
	}
}

type mihomoLiveDispatchReadModel struct{ reads, effects int }

func (r *mihomoLiveDispatchReadModel) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("generic source must not be invoked")
}
func (r *mihomoLiveDispatchReadModel) RunMihomoLive(context.Context, MihomoLiveCommandAdmission, string, ...string) ([]byte, error) {
	r.effects++
	return nil, errors.New("effect must not be invoked")
}
func (r *mihomoLiveDispatchReadModel) RunMihomoLiveRead(context.Context, string, ...string) ([]byte, error) {
	r.reads++
	return []byte("closed read model"), nil
}
func TestMihomoLiveCommandNumericIPFlagsRemainReadOnly(t *testing.T) {
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	m := New(t.TempDir())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	base := &mihomoLiveDispatchReadModel{}
	runner := &mihomoLiveCommandRunner{adapter: a, base: base}
	proxy := &ProxyTunnelAdapter{EngineID: "mihomo", IP: "/protected/ip", IPTables: "/protected/iptables", IP6Tables: "/protected/ip6tables", Runner: runner}
	scope := &executionResourceScope{manager: m, adapter: "mihomo", adapterOwner: a}
	resource := &mihomoLiveResource{adapter: a, scope: scope, proxy: proxy}
	resource.self = resource
	scope.mihomoLive = resource
	ctx := context.WithValue(context.Background(), syntheticExecutionRegistrarKey{}, scope)
	for _, args := range [][]string{{"-N", "-4", "-j", "rule", "show"}, {"-N", "-6", "-j", "route", "show", "table", "207"}, {"-j", "link", "show", "dev", "add"}} {
		if _, err := runner.Run(ctx, proxy.IP, args...); err != nil {
			t.Fatal(args, err)
		}
	}
	if base.reads != 3 || base.effects != 0 {
		t.Fatal("numeric read invoked effect token", base.reads, base.effects)
	}
	if !mihomoLiveEffectCommand(false, []string{"-t", "filter", "-N", "RZP_owned"}) {
		t.Fatal("iptables chain creation lost effect admission")
	}
}

// Actual Cmd.Start/control barrier; source/registry are a deliberately minimal
// private model. This is not a protected-tool or routed live workflow proof.
func TestMihomoLiveCommandOriginalShortStartRefusals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gate := &operationgate.Gate{}
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
		t.Fatal(err)
	}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	m := New(t.TempDir())
	if err = m.Register(a); err != nil {
		t.Fatal(err)
	}
	r := &mihomoLiveResource{adapter: a, scope: &executionResourceScope{manager: m}, control: control}
	r.self = r
	makeCall := func() *mihomoLiveCommand {
		c := &mihomoLiveCommand{owner: r, name: "native-helper", args: []string{"fixed"}, review: strings.Repeat("a", 64), open: true}
		c.self = c
		return c
	}
	for _, scenario := range []string{"success", "cancel", "wrong-argv", "wrong-review", "foreign-token", "closed", "copied", "callback-error"} {
		t.Run(scenario, func(t *testing.T) {
			c := makeCall()
			callctx := context.WithValue(held, mihomoLiveCommandKey{}, c)
			args := append([]string(nil), c.args...)
			review := c.review
			if scenario == "cancel" {
				cancelled, done := context.WithCancel(callctx)
				done()
				callctx = cancelled
			}
			if scenario == "wrong-argv" {
				args = []string{"changed"}
			}
			if scenario == "wrong-review" {
				review = strings.Repeat("b", 64)
			}
			if scenario == "foreign-token" {
				callctx = context.WithValue(callctx, mihomoLiveCommandKey{}, makeCall())
			}
			if scenario == "closed" {
				c.open = false
			}
			if scenario == "copied" {
				c = &mihomoLiveCommand{self: c, owner: c.owner, name: c.name, args: c.args, review: c.review, open: true}
			}
			started := 0
			var command *exec.Cmd
			sentinel := errors.New("actual callback failed")
			err := c.WithStart(callctx, c.name, args, review, func() error {
				started++
				if scenario == "callback-error" {
					return sentinel
				}
				command = exec.Command(os.Args[0], "-test.run=^TestMihomoLiveCommandNativeHelper$")
				command.Env = append(os.Environ(), "RAZVILKA_MIHOMO_COMMAND_HELPER=1")
				return command.Start()
			})
			if command != nil && command.Process != nil {
				err = errors.Join(err, command.Wait())
			}
			if scenario == "success" {
				if err != nil || started != 1 {
					t.Fatal("actual admitted child", started, err)
				}
			} else if scenario == "callback-error" {
				if !errors.Is(err, sentinel) || started != 1 {
					t.Fatal("callback error lost", err)
				}
			} else if err == nil || started != 0 {
				t.Fatal("invalid command started", started, err)
			}
			if c.WithStart(callctx, c.name, args, review, func() error { t.Fatal("repeated native command started"); return nil }) == nil {
				t.Fatal("replay accepted")
			}
			c.mu.Lock()
			c.open = false
			c.mu.Unlock()
			if c.WithStart(callctx, c.name, args, review, func() error { t.Fatal("escaped native command started"); return nil }) == nil {
				t.Fatal("closed call accepted")
			}
		})
	}
}
