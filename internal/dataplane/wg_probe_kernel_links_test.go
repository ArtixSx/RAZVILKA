package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Only detached kernel facts are modeled. The fixture retains the genuine
// Manager/control/material owner and actual child admission/Start/Wait.
type wgProbeKernelModel struct {
	*wgCommandProcessModel
	links []physicalscope.WGKernelLink
	err   error
	after func(context.Context)
	reads atomic.Int32
}

func (m *wgProbeKernelModel) ReadWGKernelLinks(ctx context.Context, _ netidentity.Identity) ([]physicalscope.WGKernelLink, error) {
	m.reads.Add(1)
	if m.after != nil {
		m.after(ctx)
	}
	return m.links, m.err
}

func wgProbeKernelFixture(t *testing.T, engine string, companion bool) (*WARPWireGuardAdapter, *wgOperationOwner, context.Context, *wgProbeKernelModel, string) {
	t.Helper()
	a, _, plan, _, _ := wgNetworkLifecycleFixture(t, true)
	a.EngineID = engine
	marker := filepath.Join(t.TempDir(), "commands")
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	model := &wgProbeKernelModel{links: []physicalscope.WGKernelLink{{Name: "lo", Index: 1}, {Name: "foreign-wg", Index: 77, Kind: "wireguard"}, {Name: "foreign-awg", Index: 78, Kind: "amneziawg"}}}
	a, owner, ctx, _, _, _ := wgNetworkCommandOwnerForPlan(t, a, plan, func(tools *WGCommandTools) {
		model.wgCommandProcessModel = &wgCommandProcessModel{review: tools.ReviewSHA256}
		tools.Runner = model
		if !companion {
			if engine == "amneziawg" {
				tools.WG = ""
			} else {
				tools.AWG = ""
			}
		}
	})
	return a, owner, ctx, model, marker
}

func wgProbeCommands(t *testing.T, marker string) string {
	t.Helper()
	data, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestWGProbeKernelOriginalOwnerCompleteBackendIdentity(t *testing.T) {
	for _, engine := range []string{"wireguard", "amneziawg"} {
		t.Run(engine, func(t *testing.T) {
			a, _, ctx, model, marker := wgProbeKernelFixture(t, engine, true)
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", "foreign-wg\t(none)\nforeign-awg\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
			if err := a.ensureWGCanaryIdentityFree(ctx, []byte(testOwnWireGuardProfile(""))); err != nil {
				t.Fatal(err)
			}
			if model.reads.Load() != 1 || wgProbeCommands(t, marker) != strings.Repeat("show all public-key\n", 2) {
				t.Fatal("kernel/public identity path escaped original source")
			}
			rows, err := a.wgProbeLinks(ctx)
			if err != nil || len(rows) != 3 {
				t.Fatal("complete observation", err)
			}
			rows[0].name = "detached"
			if model.links[0].Name != "lo" {
				t.Fatal("returned rows alias the source")
			}
		})
	}
}

func TestWGProbeKernelRefusalNeverFallsBackToJSON(t *testing.T) {
	for _, tc := range []string{"transport", "empty", "duplicate-name", "duplicate-index", "missing-companion", "omitted-identity", "malformed-identity", "reused-candidate"} {
		t.Run(tc, func(t *testing.T) {
			a, _, ctx, model, marker := wgProbeKernelFixture(t, "wireguard", tc != "missing-companion")
			public, err := wgRuntimePublicKey([]byte(testOwnWireGuardProfile("")))
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", "foreign-wg\t(none)\nforeign-awg\t(none)\n")
			want := ErrWGCanaryIdentityInspection
			switch tc {
			case "transport":
				model.err = errors.New("RTM transport unavailable")
			case "empty":
				model.links = nil
			case "duplicate-name":
				model.links[2].Name = model.links[1].Name
			case "duplicate-index":
				model.links[2].Index = model.links[1].Index
			case "omitted-identity":
				t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", "foreign-wg\t(none)\n")
			case "malformed-identity":
				t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", "foreign-wg invalid\n")
			case "reused-candidate":
				t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", "foreign-wg\t"+public+"\n")
				want = ErrWGCanaryIdentityInUse
			}
			if err := a.ensureWGCanaryIdentityFree(ctx, []byte(testOwnWireGuardProfile(""))); !errors.Is(err, want) {
				t.Fatal("unsafe identity admitted", err)
			}
			commands := wgProbeCommands(t, marker)
			for _, line := range strings.Split(strings.TrimSpace(commands), "\n") {
				if line != "" && line != "show all public-key" {
					t.Fatal("fallback or mutation", commands)
				}
			}
			if tc == "transport" || tc == "empty" || strings.HasPrefix(tc, "duplicate") || tc == "missing-companion" {
				if commands != "" {
					t.Fatal("command after refused kernel observation", commands)
				}
			}
		})
	}
}

func TestWGProbeKernelBoundSourceWithoutKernelCapabilityRefuses(t *testing.T) {
	a, _, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
	marker := filepath.Join(t.TempDir(), "commands")
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	if rows, err := a.wgProbeLinks(ctx); !errors.Is(err, ErrWGOperationOwner) || len(rows) != 0 {
		t.Fatal("bound source without kernel capability accepted", err)
	}
	if wgProbeCommands(t, marker) != "" {
		t.Fatal("unavailable original kernel source revived JSON")
	}
}

func TestWGProbeKernelOwnerAndClosingFences(t *testing.T) {
	for _, tc := range []string{"no-owner", "copied-owner", "wrong-adapter", "closed-material", "changed-tools", "closing-change", "cancelled"} {
		t.Run(tc, func(t *testing.T) {
			a, owner, ctx, model, marker := wgProbeKernelFixture(t, "wireguard", true)
			original := a.wgCommandTools
			t.Cleanup(func() { a.wgCommandTools = original })
			switch tc {
			case "no-owner":
				ctx = context.WithValue(ctx, wgOperationOwnerKey{}, nil)
			case "copied-owner":
				copied := &wgOperationOwner{self: owner, material: owner.material, scope: owner.scope, adapter: a}
				ctx = context.WithValue(ctx, wgOperationOwnerKey{}, copied)
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
				model.after = func(context.Context) { copy := *original; a.wgCommandTools = &copy }
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if rows, err := a.wgProbeLinks(ctx); err == nil || len(rows) != 0 {
				t.Fatal("stale/copied owner produced facts")
			}
			if wgProbeCommands(t, marker) != "" {
				t.Fatal("refusal revived CLI")
			}
			wantReads := int32(0)
			if tc == "closing-change" {
				wantReads = 1
			}
			if model.reads.Load() != wantReads {
				t.Fatal("source entered without original owner")
			}
			if tc == "closing-change" {
				a.wgCommandTools = original
				if _, err := a.wgProbeLinks(ctx); err == nil || model.reads.Load() != 1 {
					t.Fatal("closing revocation revived")
				}
			}
		})
	}
}

func TestWGProbeKernelCloseJoinsRead(t *testing.T) {
	a, owner, ctx, model, _ := wgProbeKernelFixture(t, "wireguard", true)
	entered, finish := make(chan struct{}), make(chan struct{})
	model.after = func(context.Context) { close(entered); <-finish }
	read := make(chan error, 1)
	go func() { _, err := a.wgProbeLinks(ctx); read <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("read not entered")
	}
	closed := make(chan error, 1)
	go func() { closed <- owner.material.Close() }()
	select {
	case <-closed:
		t.Fatal("Close did not join read")
	case <-time.After(30 * time.Millisecond):
	}
	close(finish)
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if _, err := a.wgProbeLinks(ctx); err == nil || model.reads.Load() != 1 {
		t.Fatal("closed material revived")
	}
}

func TestWGProbeKernelCancellationDiscardsFacts(t *testing.T) {
	a, _, ctx, model, _ := wgProbeKernelFixture(t, "wireguard", true)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	model.after = func(context.Context) { cancel() }
	if rows, err := a.wgProbeLinks(ctx); err == nil || len(rows) != 0 || model.reads.Load() != 1 {
		t.Fatal("cancelled observation returned facts")
	}
}

func TestWGProbeKernelOwnedExceptionStillRequiresExactPrimaryIdentity(t *testing.T) {
	for _, engine := range []string{"wireguard", "amneziawg"} {
		t.Run(engine, func(t *testing.T) {
			a, _, ctx, model, _ := wgProbeKernelFixture(t, engine, false)
			model.links = []physicalscope.WGKernelLink{{Name: a.interfaceName(), Index: 77, Kind: engine}}
			public, err := wgRuntimePublicKey([]byte(testOwnWireGuardProfile("")))
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", a.interfaceName()+"\t"+public+"\n")
			if err := a.inspectWGProbeIdentity(ctx, []byte(testOwnWireGuardProfile("")), a.interfaceName()); err != nil {
				t.Fatal(err)
			}
			if err := a.ensureWGCanaryIdentityFree(ctx, []byte(testOwnWireGuardProfile(""))); !errors.Is(err, ErrWGCanaryIdentityInUse) {
				t.Fatal("foreign candidate admitted", err)
			}
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", a.interfaceName()+"\t(none)\n")
			if err := a.inspectWGProbeIdentity(ctx, []byte(testOwnWireGuardProfile("")), a.interfaceName()); !errors.Is(err, ErrWGCanaryIdentityInspection) {
				t.Fatal("owned identity exception without matching key", err)
			}
		})
	}
}
