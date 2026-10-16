package dataplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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
