package dataplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Only detached service-table counts are modeled. The operation/control,
// Manager/material/barriers and actual rejected CLI child Start/Wait are real.
// This is not a native kernel, interface, peer or service proof.
type wgServiceKernelModel struct {
	*wgCommandProcessModel
	identity netidentity.Identity
	table    int
	iface    string
	count    int
	err      error
	after    func(context.Context)
	reads    atomic.Int32
	cli      atomic.Int32
}

func (m *wgServiceKernelModel) ReadWGKernelServiceTable(ctx context.Context, identity netidentity.Identity, table, family int, iface string) (int, error) {
	m.reads.Add(1)
	if identity != m.identity || table != m.table || iface != m.iface || family != 4 && family != 6 {
		return 0, ErrWGOperationOwner
	}
	if m.after != nil {
		m.after(ctx)
	}
	return m.count, m.err
}

func (m *wgServiceKernelModel) RunWG(ctx context.Context, owner WGCommandAdmission, name string, args ...string) ([]byte, error) {
	m.cli.Add(1)
	data, err := m.wgCommandProcessModel.RunWG(ctx, owner, name, args...)
	if err != nil {
		return data, err
	}
	// Entware4.4 rejects the requested detailed/JSON option. Preserve the
	// actual child lifecycle above; do not manufacture a successful CLI read.
	return data, errors.New("modeled Entware ip4.4 unsupported option")
}

func wgServiceKernelFixture(t *testing.T, engine string) (*WARPWireGuardAdapter, *wgOperationOwner, context.Context, *wgServiceKernelModel, string) {
	t.Helper()
	a, _, plan, _, _ := wgNetworkLifecycleFixture(t, true)
	a.EngineID = engine
	marker := filepath.Join(t.TempDir(), "commands")
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", "Option \"-N\" is unknown, try \"ip -help\".")
	m := &wgServiceKernelModel{count: 1}
	a, owner, ctx, _, _, _ := wgNetworkCommandOwnerForPlan(t, a, plan, func(tools *WGCommandTools) {
		m.wgCommandProcessModel = &wgCommandProcessModel{review: tools.ReviewSHA256}
		m.identity = tools.Identity
		tools.Runner = m
	})
	m.table, m.iface = a.table(), a.interfaceName()
	return a, owner, ctx, m, marker
}

func TestWGNetworkServiceKernelEntwarePositiveAndEmptyUseOriginalSource(t *testing.T) {
	for _, engine := range []string{"wireguard", "amneziawg"} {
		for _, family := range []int{4, 6} {
			for _, want := range []int{0, 1} {
				t.Run(fmt.Sprintf("%s/%d/%d", engine, family, want), func(t *testing.T) {
					a, _, ctx, m, marker := wgServiceKernelFixture(t, engine)
					m.count = want
					state := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: strings.Repeat("a", 64)}
					count, err := a.wgNetworkServiceTablePresence(ctx, state, family)
					if err != nil || count != want || m.reads.Load() != 1 || m.cli.Load() != 0 || wgProbeCommands(t, marker) != "" {
						t.Fatalf("held kernel service-table source ignored: count=%d want=%d kernel_reads=%d cli_reads=%d err=%v", count, want, m.reads.Load(), m.cli.Load(), err)
					}
				})
			}
		}
	}
}

func TestWGNetworkServiceKernelRefusalCannotReviveLegacyCLI(t *testing.T) {
	a, _, ctx, m, marker := wgServiceKernelFixture(t, "wireguard")
	m.err = errors.New("modeled original kernel source refused")
	state := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: strings.Repeat("a", 64)}
	count, err := a.wgNetworkServiceTablePresence(ctx, state, 4)
	if err == nil || count != 0 || m.reads.Load() != 1 || m.cli.Load() != 0 || wgProbeCommands(t, marker) != "" {
		t.Fatalf("bound refusal used legacy CLI: count=%d kernel_reads=%d cli_reads=%d err=%v", count, m.reads.Load(), m.cli.Load(), err)
	}
}

func TestWGNetworkServiceKernelOwnerAndClosingFences(t *testing.T) {
	for _, cut := range []string{"no-owner", "copied-owner", "wrong-adapter", "closed-material", "changed-tools", "closing-change", "cancel-before", "cancel-during", "invalid-count"} {
		t.Run(cut, func(t *testing.T) {
			a, owner, ctx, m, marker := wgServiceKernelFixture(t, "wireguard")
			original := a.wgCommandTools
			t.Cleanup(func() { a.wgCommandTools = original })
			switch cut {
			case "no-owner":
				ctx = context.WithValue(ctx, wgOperationOwnerKey{}, nil)
			case "copied-owner":
				ctx = context.WithValue(ctx, wgOperationOwnerKey{}, &wgOperationOwner{self: owner, material: owner.material, scope: owner.scope, adapter: a})
			case "wrong-adapter":
				copy := *a
				a = &copy
			case "closed-material":
				if err := owner.material.Close(); err != nil {
					t.Fatal(err)
				}
			case "changed-tools":
				copy := *original
				a.wgCommandTools = &copy
			case "closing-change":
				m.after = func(context.Context) { copy := *original; a.wgCommandTools = &copy }
			case "cancel-before", "cancel-during":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				if cut == "cancel-before" {
					cancel()
				} else {
					m.after = func(context.Context) { cancel() }
				}
			case "invalid-count":
				m.count = 2
			}
			state := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: strings.Repeat("a", 64)}
			if count, err := a.wgNetworkServiceTablePresence(ctx, state, 4); err == nil || count != 0 {
				t.Fatal("stale/copied original owner returned a fact")
			}
			want := int32(0)
			if cut == "closing-change" || cut == "cancel-during" || cut == "invalid-count" {
				want = 1
			}
			if m.reads.Load() != want || m.cli.Load() != 0 || wgProbeCommands(t, marker) != "" {
				t.Fatal("refused owner entered source or revived CLI", cut)
			}
			if cut == "closing-change" {
				a.wgCommandTools = original
				if n, err := a.wgNetworkServiceTablePresence(ctx, state, 4); err == nil || n != 0 || m.reads.Load() != 1 {
					t.Fatal("closing revocation revived")
				}
			}
		})
	}
}

func TestWGNetworkServiceKernelMissingCapabilityCannotUseLegacyCLI(t *testing.T) {
	a, _, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
	marker := filepath.Join(t.TempDir(), "commands")
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	state := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: strings.Repeat("a", 64)}
	if n, err := a.wgNetworkServiceTablePresence(ctx, state, 4); err == nil || n != 0 || wgProbeCommands(t, marker) != "" {
		t.Fatal("unissued capability used CLI")
	}
}

func TestWGNetworkServiceKernelMaterialCloseJoinsRead(t *testing.T) {
	a, owner, ctx, m, _ := wgServiceKernelFixture(t, "wireguard")
	entered, finish := make(chan struct{}), make(chan struct{})
	m.after = func(context.Context) { close(entered); <-finish }
	state := PolicyState{Interface: a.interfaceName(), Table: a.table(), NetworkPolicyGeneration: strings.Repeat("a", 64)}
	read := make(chan error, 1)
	go func() { _, err := a.wgNetworkServiceTablePresence(ctx, state, 4); read <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("read not entered")
	}
	closed := make(chan error, 1)
	go func() { closed <- owner.material.Close() }()
	select {
	case <-closed:
		close(finish)
		t.Fatal("Close escaped original read barrier")
	case <-time.After(30 * time.Millisecond):
	}
	close(finish)
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if n, err := a.wgNetworkServiceTablePresence(ctx, state, 4); err == nil || n != 0 || m.reads.Load() != 1 {
		t.Fatal("closed material returned presence")
	}
}
