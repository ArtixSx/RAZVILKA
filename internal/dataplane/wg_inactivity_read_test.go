package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual registered adapter/Manager, Gate/control/root, one Cmd.Start and sole
// Wait; tool closure/NI/kernel output remain explicit portable models. This
// cannot establish native inactivity, a network PASS or an execution owner.
type wgInactivityProcessModel struct {
	base       *wgCommandProcessModel
	calls      atomic.Int32
	sameCalls  atomic.Int32
	escaped    context.Context
	admission  WGCommandAdmission
	block      bool
	commandErr error // Explicit native command-exit model; actual child still Waits.
}

func (m *wgInactivityProcessModel) SameWGToolSource(other WGCommandToolRunner) bool {
	if m.base.insideLeaf.Load() {
		panic("same-source callback inside held Start")
	}
	m.sameCalls.Add(1)
	return other == m.base
}
func (m *wgInactivityProcessModel) CheckWG(ctx context.Context, identity netidentity.Identity) error {
	return m.base.CheckWG(ctx, identity)
}
func (m *wgInactivityProcessModel) RunWG(ctx context.Context, admission WGCommandAdmission, name string, args ...string) ([]byte, error) {
	m.calls.Add(1)
	m.escaped, m.admission = ctx, admission
	output := ""
	if slices.Contains(args, "link") {
		output = "[{\"ifname\":\"lo\"}]\n"
	}
	if slices.Contains(args, "rule") {
		output = "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"
	}
	if slices.Contains(args, "route") && slices.Contains(args, "-j") {
		output = "[]\n"
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(os.Environ(), "RAZVILKA_WG_COMMAND_TEST_OUTPUT="+output)
	if m.block {
		command.Env = append(command.Env, "RAZVILKA_WG_COMMAND_TEST_WAIT=1")
	}
	var buffer bytes.Buffer
	command.Stdout, command.Stderr, command.WaitDelay = &buffer, &buffer, 100*time.Millisecond
	m.base.insideLeaf.Store(true)
	startErr := admission.WithStart(ctx, name, args, m.base.review, command.Start)
	m.base.insideLeaf.Store(false)
	if command.Process == nil {
		return nil, startErr
	}
	waitErr := command.Wait()
	return buffer.Bytes(), errors.Join(startErr, waitErr, m.commandErr)
}

func wgInactivityFixture(t *testing.T, absentCLI bool) (*wgSourceReadFixture, *WGInactivityRead, *wgInactivityProcessModel) {
	t.Helper()
	f := newWGSourceReadFixture(t)
	m := &wgInactivityProcessModel{base: f.model}
	tools := *f.a.wgCommandTools
	tools.Runner = m
	if absentCLI {
		a := NewAmneziaWGAdapter(f.a.Configs, f.manager.StateRoot)
		if err := f.manager.Register(a); err != nil {
			t.Fatal(err)
		}
		tools.EngineID, tools.WG, tools.AWG = "amneziawg", "", ""
		// Distinct fixed alias for the actual Go child used as the IP model.
		ip := filepath.Join(t.TempDir(), "ip-model.exe")
		binary, err := os.ReadFile(tools.IP)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ip, binary, 0700); err != nil {
			t.Fatal(err)
		}
		tools.IP = ip
	}
	r, err := ReviewWGInactivityRead(f.ctx, context.Background(), f.manager, f.control, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return f, r, m
}

func TestWGInactivityReadOriginalFreshOperationAndOneUse(t *testing.T) {
	f, r, m := wgInactivityFixture(t, false)
	var saved context.Context
	args := []string{"show", "all", "public-key"}
	if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
		saved = c
		_, err := r.Run(c, r.tools.WG, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	escaped, closeEscaped := context.WithTimeout(context.WithoutCancel(saved), 3*time.Second)
	defer closeEscaped()
	if _, err := r.Run(escaped, r.tools.WG, args...); err == nil {
		t.Fatal("escaped session read")
	}
	starts := 0
	if err := m.admission.WithStart(m.escaped, r.tools.WG, args, r.tools.ReviewSHA256, func() error { starts++; return nil }); err == nil || starts != 0 {
		t.Fatal("one-use read admission escaped")
	}
	if m.sameCalls.Load() != 1 {
		t.Fatal("full same-source callback reentered pure Start")
	}
	f.cancel()
	f.release()
	if err := f.read.Current(f.ctx); err == nil {
		t.Fatal("ordinary original forward source revived")
	}
	fresh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	fresh, release, err := f.gate.ExclusiveContext(fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := r.WithCurrent(fresh, nil, func(c context.Context) error { _, err := r.Run(c, r.tools.WG, args...); return err }); err != nil {
		t.Fatal("distinct original inactivity source lost fresh same-Gate operation", err)
	}
}

func TestWGInactivityReadCleanupNeedsOriginalUnreleasedCapability(t *testing.T) {
	f, r, _ := wgInactivityFixture(t, false)
	cleanup, err := f.control.ReviewExclusiveCleanup(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.cancel()
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	consume := func(ctx context.Context) error {
		_, err := r.Run(ctx, r.tools.WG, "show", "all", "public-key")
		return err
	}
	if err := r.WithCurrent(c, nil, consume); err == nil {
		t.Fatal("bare fresh context acquired forward operation")
	}
	if err := r.WithCurrent(c, cleanup, consume); err != nil {
		t.Fatal("same held original cleanup read refused", err)
	}
	f.release()
	if err := r.WithCurrent(c, cleanup, consume); err == nil {
		t.Fatal("released cleanup capability revived")
	}
}

func TestWGInactivityReadAbsentCLIStillRunsCompleteExistingObserver(t *testing.T) {
	f, r, m := wgInactivityFixture(t, true)
	if r.tools.WG != "" || r.tools.AWG != "" {
		t.Fatal("absent primary gained fallback CLI")
	}
	// The actual platform process reader can refuse on Windows. Its refusal
	// must not become absence PASS. Complete prior IP observations still run.
	err := r.VerifyRuntimeInactive(f.ctx, nil)
	if m.calls.Load() < 10 {
		t.Fatal("missing CLI bypassed existing whole observer", m.calls.Load(), err)
	}
	if err == nil && os.PathSeparator == '\\' {
		t.Fatal("unsupported process inventory became inactive")
	}
	before := m.calls.Load()
	if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
		_, err := r.Run(c, "unissued-wg", "show", "all", "public-key")
		return err
	}); err == nil || m.calls.Load() != before {
		t.Fatal("absent CLI executed fallback")
	}
}

func TestWGInactivityReadForeignClosedAndChangedOwnersRefuse(t *testing.T) {
	for _, changed := range []string{"closed", "foreign-operation", "registry", "adapter", "tool-binding", "runtime-root", "root-appearance"} {
		t.Run(changed, func(t *testing.T) {
			f, r, m := wgInactivityFixture(t, false)
			ctx := f.ctx
			switch changed {
			case "closed":
				_ = r.Close()
			case "foreign-operation":
				foreign, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var release func()
				var err error
				ctx, release, err = (&operationgate.Gate{}).ExclusiveContext(foreign)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "registry":
				if err := f.manager.Register(NewAmneziaWGAdapter(f.a.Configs, f.manager.StateRoot)); err != nil {
					t.Fatal(err)
				}
			case "adapter":
				f.a.Interface = "different-wg"
			case "tool-binding":
				f.a.wgCommandTools.ReviewSHA256 = strings.Repeat("b", 64)
			case "runtime-root":
				f.a.StateRoot += "-other"
			}
			err := r.WithCurrent(ctx, nil, func(c context.Context) error {
				if changed == "root-appearance" {
					return os.MkdirAll(f.a.StateRoot, 0700)
				}
				_, err := r.Run(c, r.tools.WG, "show", "all", "public-key")
				return err
			})
			if err == nil || m.calls.Load() != 0 {
				t.Fatal("changed/foreign original read issued", changed, err, m.calls.Load())
			}
		})
	}
	f, r, _ := wgInactivityFixture(t, false)
	copy := &WGInactivityRead{self: r, manager: r.manager}
	if err := copy.WithCurrent(f.ctx, nil, func(context.Context) error { return nil }); err == nil {
		t.Fatal("copied source adopted")
	}
}

func TestWGInactivityReadExactABIRejectsEffectsAndPrivateReadback(t *testing.T) {
	f, r, m := wgInactivityFixture(t, false)
	for _, args := range [][]string{{"setconf", "rz-wg", "/private/config"}, {"show", "all", "dump"}, {"show", "rz-wg", "private-key"}, {"link", "delete", "dev", "rz-wg"}, {"route", "flush", "table", "206"}, {"-batch", "/private/batch"}, {"-N", "-N", "rule", "show"}, {"-N", "route", "show", "table", "254"}, {"-t", "filter", "-F"}} {
		if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error { _, err := r.Run(c, r.tools.WG, args...); return err }); err == nil {
			t.Fatal("effect/private read admitted", args)
		}
	}
	if m.calls.Load() != 0 {
		t.Fatal("ABI refusal reached child source")
	}
}

func TestWGInactivityReadCloseCancelsAndJoinsActualChildWait(t *testing.T) {
	f, r, m := wgInactivityFixture(t, false)
	m.block = true
	done := make(chan error, 1)
	go func() {
		done <- r.WithCurrent(f.ctx, nil, func(c context.Context) error { _, err := r.Run(c, r.tools.WG, "show", "all", "public-key"); return err })
	}()
	limit := time.Now().Add(3 * time.Second)
	for {
		if data, err := os.ReadFile(f.marker); err == nil && len(data) > 0 {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("actual read child did not enter wait model")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked read child supplied observation")
		}
	case <-time.After(time.Second):
		t.Fatal("source Close returned before actual Wait/session join")
	}
	if err := r.WithCurrent(f.ctx, nil, func(context.Context) error { return nil }); err == nil {
		t.Fatal("closed reader revived")
	}
}

func TestWGInactivityReadIPABIIsNumericAndAdapterFinite(t *testing.T) {
	f, r, _ := wgInactivityFixture(t, false)
	tools := r.tools
	tools.IP = filepath.Join(f.manager.StateRoot, "fixed-ip")
	for _, args := range [][]string{{"rule", "show"}, {"-6", "rule", "show"}, {"-N", "-6", "rule", "show"}, {"-j", "link", "show"}, {"-N", "-j", "route", "show", "table", "206"}, {"-N", "-6", "route", "show", "table", "219"}} {
		actual, valid := wgInactivityReadArguments(r.adapter, tools, tools.IP, args)
		if !valid {
			t.Fatal("existing finite numeric read refused", args)
		}
		if slices.Contains(args, "rule") && !slices.Contains(actual, "-N") {
			t.Fatal("bare RPDB names remained eligible")
		}
	}
	for _, args := range [][]string{{"-N", "-N", "rule", "show"}, {"-N", "-4", "-6", "rule", "show"}, {"-j", "link", "show", "dev", "other"}, {"-N", "route", "show", "table", "254"}, {"-N", "route", "show", "table", "0206"}, {"-N", "route", "show", "table", "all"}, {"-j", "route", "get", "1.1.1.1"}, {"link", "delete", "dev", "rz-wg"}} {
		if _, valid := wgInactivityReadArguments(r.adapter, tools, tools.IP, args); valid {
			t.Fatal("broad/non-numeric read/effect admitted", args)
		}
	}
}

func TestWGInactivityReadCurrentFilesUsesOriginalLiveSessionWithoutCallbacks(t *testing.T) {
	f, r, m := wgInactivityFixture(t, false)
	var saved context.Context
	if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
		saved = c
		m.base.insideLeaf.Store(true)
		defer m.base.insideLeaf.Store(false)
		return r.CurrentFiles(c)
	}); err != nil {
		t.Fatal("pure file bookend called full source callback", err)
	}
	escaped, cancel := context.WithTimeout(context.WithoutCancel(saved), time.Second)
	defer cancel()
	if err := r.CurrentFiles(escaped); err == nil {
		t.Fatal("closed session supplied file bookend")
	}
	if m.calls.Load() != 0 || m.sameCalls.Load() != 1 {
		t.Fatal("file bookend issued tool callback")
	}
}

func TestWGInactivityReadCurrentFilesRefusesChangedOriginalSubtree(t *testing.T) {
	for _, mutation := range []string{"bytes", "new-file", "removed-file", "directory", "same-bytes-replacement"} {
		t.Run(mutation, func(t *testing.T) {
			f, r, _ := wgInactivityFixture(t, false)
			if err := os.MkdirAll(f.a.StateRoot, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.a.StateRoot, "comparison-only.json")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
				if err := r.CurrentFiles(c); err != nil {
					return err
				}
				var err error
				switch mutation {
				case "bytes":
					err = os.WriteFile(path, []byte("modified"), 0600)
				case "new-file":
					err = os.WriteFile(filepath.Join(f.a.StateRoot, "new.json"), []byte("new"), 0600)
				case "removed-file":
					err = os.Remove(path)
				case "directory":
					err = os.Mkdir(filepath.Join(f.a.StateRoot, "new-dir"), 0700)
				case "same-bytes-replacement":
					if err = os.Rename(path, path+"-retained"); err == nil {
						err = os.WriteFile(path, []byte("original"), 0600)
					}
				}
				if err != nil {
					t.Fatal("could not exercise actual file mutation", err)
				}
				if err := r.CurrentFiles(c); err == nil {
					t.Fatal("changed original subtree passed pure bookend")
				}
				return nil
			}); err == nil {
				t.Fatal("changed subtree passed whole read session")
			}
		})
	}
}

func TestWGInactivityReadPreservesDiagnosticOnlyWithCurrentOriginalSource(t *testing.T) {
	f, r, m := wgInactivityFixture(t, true)
	m.commandErr = errors.New("model ip command exit")
	if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
		out, err := r.Run(c, r.tools.IP, "-N", "-j", "route", "show", "table", "205")
		if !errors.Is(err, m.commandErr) || string(out) != "[]\n" {
			t.Fatal("original bounded command diagnostic discarded", string(out), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWGInactivityReadCloseKeepsOriginalSessionDescriptorFailure(t *testing.T) {
	f, r, _ := wgInactivityFixture(t, false)
	if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
		s := c.Value(wgInactivitySessionKey{}).(*wgInactivityReadSession)
		return s.roots.nodes[0].file.Close() // Actual descriptor-close fault model.
	}); err == nil {
		t.Fatal("failed retained session descriptor close erased")
	}
	for i := 0; i < 2; i++ {
		if err := r.Close(); err == nil {
			t.Fatal("source Close erased original session descriptor failure", i)
		}
	}
}
