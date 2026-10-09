package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

// Actual Store/profile, Manager/registration, Gate/control/root and child
// Start/Wait. Only tool closure/NI and route JSON are explicit models, never
// native WAN/traffic/App Ready evidence. No Plan/Paths/PASS is fabricated.
type wgSourceReadFixture struct {
	a            *WARPWireGuardAdapter
	manager      *Manager
	gate         *operationgate.Gate
	control      *operationgate.ControlEpochReview
	ctx          context.Context
	cancel       context.CancelFunc
	release      func()
	root, marker string
	model        *wgCommandProcessModel
	profiles     *wireguardprofile.Store
	read         *WGSourceReadReview
}

func newWGSourceReadFixture(t *testing.T) *wgSourceReadFixture {
	t.Helper()
	f := &wgSourceReadFixture{gate: &operationgate.Gate{}, model: &wgCommandProcessModel{review: strings.Repeat("a", 64)}}
	root := t.TempDir()
	f.manager = New(filepath.Join(root, "dataplane"))
	if err := os.MkdirAll(f.manager.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	configs.LiveRoot = filepath.Join(root, "live")
	f.a = NewWireGuardAdapter(configs, f.manager.StateRoot)
	f.profiles = wireguardprofile.New(filepath.Join(root, "profiles"))
	f.a.Profiles = f.profiles
	if _, err := f.profiles.Put(context.Background(), "server", "Actual imported profile", strings.ReplaceAll(testOwnWireGuardProfile(""), "vpn.example.com", "1.1.1.1"), ""); err != nil {
		t.Fatal(err)
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tools := WGCommandTools{EngineID: "wireguard", WG: program, IP: program, IPTables: program, IP6Tables: program, ReviewSHA256: f.model.review, Identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 123}, Provider: netidentity.NewProcProvider(), Runner: f.model}
	if err := f.a.BindWGCommandTools(tools); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Register(f.a); err != nil {
		t.Fatal(err)
	}
	f.ctx, f.cancel = context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(f.cancel)
	f.ctx, f.release, err = f.gate.ExclusiveContext(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.release)
	f.root = filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(f.ctx, f.root); err != nil {
		t.Fatal(err)
	}
	f.control, err = f.gate.ReviewControlEpoch(f.ctx, f.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.control.Close() })
	f.marker = filepath.Join(root, "child-started")
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", f.marker)
	f.read, err = ReviewWGSourceRead(f.ctx, f.manager, f.control, "wireguard")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.read.Close() })
	return f
}

func TestWGSourceReadActualOriginalOneUseAndFiniteReadABI(t *testing.T) {
	f := newWGSourceReadFixture(t)
	args := []string{"show", "all", "public-key"}
	if _, err := f.read.Run(f.ctx, f.a.WG, args...); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(f.marker)
	if err != nil || string(actual) != "show all public-key\n" {
		t.Fatal("actual child did not run exact read", string(actual), err)
	}
	i := f.model.admission.(*wgSourceReadInvocation)
	starts := 0
	for _, ctx := range []context.Context{f.model.escaped, context.WithValue(f.model.escaped, wgSourceReadKey{}, nil), context.Background()} {
		if err := i.WithStart(ctx, f.a.WG, args, f.model.review, func() error { starts++; return nil }); !errors.Is(err, ErrWGOperationOwner) {
			t.Fatal("escaped read carrier admitted", err)
		}
	}
	copied := &wgSourceReadInvocation{self: i, open: true, owner: i.owner, name: i.name, review: i.review, args: append([]string(nil), i.args...)}
	if err := copied.WithStart(context.WithValue(f.model.escaped, wgSourceReadKey{}, copied), f.a.WG, args, f.model.review, func() error { starts++; return nil }); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("copied carrier admitted", err)
	}
	if starts != 0 {
		t.Fatal("escaped/copy reached Start")
	}
	if err := os.Remove(f.marker); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"show", "all", "dump"}, {"show", "rz-wg", "private-key"}, {"set", "rz-wg", "fwmark", "0"}, {"route", "add", "default", "dev", "rz-wg"}, {"-j", "route", "get", "127.0.0.1", "mark", "0"}, {"-6", "-j", "route", "get", "1.1.1.1", "mark", "0"}, {"-j", "route", "get", "1.1.1.1", "mark", "3"}} {
		if _, err := f.read.Run(f.ctx, f.a.WG, args...); !errors.Is(err, ErrWGOperationOwner) {
			t.Fatal("non-source ABI admitted", args, err)
		}
	}
	if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
		t.Fatal("refused ABI ran child", err)
	}
	if err := f.read.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.read.Current(f.ctx); err == nil {
		t.Fatal("closed reader survived")
	}
	if err := f.control.Current(f.ctx); err != nil {
		t.Fatal("source closed caller control", err)
	}
	if err := f.model.CheckWG(f.ctx, f.a.wgCommandTools.Identity); err != nil {
		t.Fatal("source closed shared tools", err)
	}
}

func TestWGSourceProfileActualCaptureNumericWANAndRevocation(t *testing.T) {
	f := newWGSourceReadFixture(t)
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_OUTPUT", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.2","table":254,"flags":[]}]`)
	profile, err := f.read.CaptureProfile(f.ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := profile.Observation(f.ctx)
	if err != nil || meta.EngineID != "wireguard" || meta.ProfileID != "server" || len(meta.Revision) != 64 || len(meta.ContentSHA256) != 64 {
		t.Fatal("actual metadata unavailable", meta, err)
	}
	wan, err := f.read.ObserveNumericEndpoint(f.ctx, profile)
	if err != nil || wan.Original != "1.1.1.1:51820" || wan.Endpoint != wan.Original || wan.Device != "eth0" || wan.Source != "192.0.2.2" || !wan.ExpiresAt.IsZero() {
		t.Fatal("existing parser did not read WAN", wan, err)
	}
	wan.Device, meta.Revision = "caller-copy", "caller-copy"
	if err := profile.Current(f.ctx); err != nil {
		t.Fatal("detached observation changed capture", err)
	}
	copied := &WGSourceProfileCapture{self: profile, reader: f.read}
	if _, err := f.read.ObserveNumericEndpoint(f.ctx, copied); err == nil {
		t.Fatal("copied capture admitted")
	}
	actual, err := f.a.Profiles.Get(f.ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.profiles.Put(f.ctx, "server", "changed name", actual.Config(), actual.Public().Revision); err != nil {
		t.Fatal(err)
	}
	if err := profile.Current(f.ctx); err == nil {
		t.Fatal("changed actual profile accepted")
	}
	if _, err := f.a.Configs.Stage("wireguard", "main", actual.Config()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.read.CaptureProfile(f.ctx, "main"); err == nil {
		t.Fatal("staged main became source permission")
	}
}

func TestWGSourceReadCannotReviveAfterOriginalReleaseOrStop(t *testing.T) {
	for _, mode := range []string{"released", "stopped", "registry", "tools", "root"} {
		t.Run(mode, func(t *testing.T) {
			f := newWGSourceReadFixture(t)
			ctx := f.ctx
			switch mode {
			case "released":
				f.release()
				var err error
				ctx, f.release, err = f.gate.ExclusiveContext(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer f.release()
			case "stopped":
				if _, err := operationgate.RequestSelfUpdateStop(context.Background(), f.root, strings.Repeat("a", 32), 7); err != nil {
					t.Fatal(err)
				}
			case "registry":
				if err := f.manager.Register(NewAmneziaWGAdapter(f.a.Configs, f.manager.StateRoot)); err != nil {
					t.Fatal(err)
				}
			case "tools":
				f.a.wgCommandTools.ReviewSHA256 = strings.Repeat("b", 64)
			case "root":
				f.manager.StateRoot = filepath.Join(t.TempDir(), "different")
			}
			if err := f.read.Current(ctx); err == nil {
				t.Fatal("source survived original owner change")
			}
			if _, err := f.read.Run(ctx, f.a.WG, "show", "all", "public-key"); err == nil {
				t.Fatal("revoked source started child")
			}
			if _, err := os.Stat(f.marker); !os.IsNotExist(err) {
				t.Fatal("changed owner ran child", err)
			}
		})
	}
}

type wgSourceWaitModel struct {
	*wgCommandProcessModel
	waited, returnWait chan struct{}
}

func (m *wgSourceWaitModel) RunWG(ctx context.Context, admission WGCommandAdmission, name string, args ...string) ([]byte, error) {
	out, err := m.wgCommandProcessModel.RunWG(ctx, admission, name, args...)
	close(m.waited) // the actual child Wait has returned
	<-m.returnWait
	return out, err
}

func TestWGSourceReadCloseCancelsAndJoinsActualWait(t *testing.T) {
	f := newWGSourceReadFixture(t)
	if err := f.read.Close(); err != nil {
		t.Fatal(err)
	}
	m := &wgSourceWaitModel{wgCommandProcessModel: f.model, waited: make(chan struct{}), returnWait: make(chan struct{})}
	finishWait := sync.OnceFunc(func() { close(m.returnWait) })
	defer finishWait()
	defer f.cancel()
	f.a.wgCommandTools.Runner = m // explicit test source, captured BEFORE reader creation
	var err error
	f.read, err = ReviewWGSourceRead(f.ctx, f.manager, f.control, "wireguard")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_WAIT", "1")
	run := make(chan error, 1)
	go func() { _, err := f.read.Run(f.ctx, f.a.WG, "show", "all", "public-key"); run <- err }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(f.marker); err == nil {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("actual child Start did not complete")
		}
	}
	closed := make(chan error, 2)
	go func() { closed <- f.read.Close() }()
	go func() { closed <- f.read.Close() }()
	select {
	case <-m.waited:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel/join actual child Wait")
	}
	select {
	case err := <-closed:
		t.Fatal("Close returned before original RunWG joined", err)
	default:
	}
	finishWait()
	if err := <-run; err == nil {
		t.Fatal("cancelled read returned output")
	}
	for range 2 {
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	}
	if err := f.control.Current(f.ctx); err != nil {
		t.Fatal("Close released original operation/control", err)
	}
}
