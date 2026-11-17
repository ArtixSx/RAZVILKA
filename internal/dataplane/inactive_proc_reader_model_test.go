package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Explicit ordinary-file model, unavailable in any production build. It does
// not claim procfs, namespace coverage, or kernel process terminal evidence.
type modelInactiveProcPass struct {
	ctx    context.Context
	root   string
	self   int
	link   func(string) (string, error)
	closed bool
}
type modelInactiveProcPID struct {
	self                         *modelInactiveProcPID
	pass                         *modelInactiveProcPass
	pid                          int
	path                         string
	image                        os.FileInfo
	ticks                        string
	state                        byte
	threads                      int
	gone, terminalZombie, closed bool
}

func modelInactiveProcFactory(link func(string) (string, error)) inactiveProcFactory {
	return func(ctx context.Context, root string, self int) (inactiveProcPass, error) {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, ErrProxyRuntimeInactive
		}
		return &modelInactiveProcPass{ctx: ctx, root: root, self: self, link: link}, nil
	}
}
func (p *modelInactiveProcPass) Entries() ([]os.DirEntry, error) {
	if p.closed {
		return nil, ErrProxyRuntimeInactive
	}
	f, err := os.Open(p.root)
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(8193)
	closeErr := f.Close()
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if len(entries) == 0 || len(entries) > 8192 {
		return nil, ErrProxyRuntimeInactive
	}
	return entries, errors.Join(err, closeErr)
}
func (p *modelInactiveProcPass) OpenPID(pid int) (inactiveProcPID, error) {
	path := filepath.Join(p.root, strconv.Itoa(pid))
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrProxyRuntimeInactive
	}
	h := &modelInactiveProcPID{pass: p, pid: pid, path: path, image: info}
	h.self = h
	return h, p.ctx.Err()
}
func (p *modelInactiveProcPass) GoneBeforeOpen(pid int) bool {
	_, err := os.Lstat(filepath.Join(p.root, strconv.Itoa(pid)))
	return !p.closed && p.ctx.Err() == nil && pid != p.self && os.IsNotExist(err)
}
func (p *modelInactiveProcPass) Close() error {
	if p.closed {
		return ErrProxyRuntimeInactive
	}
	p.closed = true
	return p.ctx.Err()
}
func (h *modelInactiveProcPID) Current() error {
	if h.self != h || h.closed || h.pass.closed {
		return ErrProxyRuntimeInactive
	}
	if err := h.pass.ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(h.path)
	if h.gone {
		if os.IsNotExist(err) {
			return nil
		}
		return ErrProxyRuntimeInactive
	}
	if err != nil || !os.SameFile(info, h.image) {
		return errors.Join(ErrProxyRuntimeInactive, err)
	}
	return nil
}
func (h *modelInactiveProcPID) read(name string, limit int64) ([]byte, error) {
	if err := h.Current(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(h.path, name))
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if len(raw) > int(limit) {
		return nil, ErrProxyRuntimeInactive
	}
	return raw, errors.Join(readErr, closeErr, h.Current())
}
func (h *modelInactiveProcPID) Stat() ([]byte, error) {
	raw, err := h.read("stat", 16<<10)
	if err != nil {
		return nil, err
	}
	state, ticks, threads, err := inactiveProcThreads(raw, h.pid)
	if err != nil || h.ticks != "" && h.ticks != ticks {
		return nil, &inactiveProcStatFailure{birth: err == nil}
	}
	if h.ticks == "" {
		h.ticks = ticks
	}
	h.state, h.threads = state, threads
	return raw, nil
}
func (h *modelInactiveProcPID) Command() ([]byte, error) { return h.read("cmdline", 64<<10) }
func (h *modelInactiveProcPID) Executable() (string, error) {
	if err := h.Current(); err != nil {
		return "", err
	}
	value, err := h.pass.link(filepath.Join(h.path, "exe"))
	return value, errors.Join(err, h.Current())
}
func (h *modelInactiveProcPID) Terminal() bool {
	if h.self != h || h.closed || h.pass.closed || h.pass.ctx.Err() != nil || h.pid == h.pass.self || h.state == 'X' || h.state == 'x' || h.state == 'Z' && h.threads != 1 {
		return false
	}
	if h.pass.GoneBeforeOpen(h.pid) {
		h.gone = true
		return h.Current() == nil
	}
	for i := 0; i < 2; i++ {
		raw, err := h.read("stat", 16<<10)
		if err != nil {
			return false
		}
		state, ticks, threads, err := inactiveProcThreads(raw, h.pid)
		if err != nil || h.ticks == "" || ticks != h.ticks || state != 'Z' || threads != 1 {
			return false
		}
	}
	h.terminalZombie = true
	return h.Current() == nil
}
func (h *modelInactiveProcPID) Close() error {
	if h.closed {
		return ErrProxyRuntimeInactive
	}
	err := h.Current()
	if (h.state == 'Z' || h.state == 'X' || h.state == 'x') && !h.terminalZombie && !h.gone {
		err = errors.Join(err, ErrProxyRuntimeInactive)
	}
	if h.terminalZombie && err == nil {
		raw, readErr := h.read("stat", 16<<10)
		state, ticks, threads, parseErr := inactiveProcThreads(raw, h.pid)
		if readErr != nil || parseErr != nil || state != 'Z' || threads != 1 || ticks != h.ticks {
			err = errors.Join(ErrProxyRuntimeInactive, readErr, parseErr)
		}
	}
	h.closed = true
	return err
}

func inactiveReaderStat(pid int, state byte, threads, ticks string) []byte {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[17], fields[19] = string(state), threads, ticks
	return []byte(fmt.Sprintf("%d (fixture) %s\n", pid, strings.Join(fields, " ")))
}

func TestInactiveProcCallerTerminalContracts(t *testing.T) {
	for _, engine := range []string{"proxy", "dns", "nfq"} {
		for _, tc := range []struct {
			name    string
			state   byte
			threads string
			accept  bool
		}{
			{"z1", 'Z', "1", true}, {"z2", 'Z', "2", false}, {"X", 'X', "1", false}, {"x", 'x', "1", false}, {"zero", 'Z', "0", false},
		} {
			t.Run(engine+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				var root string
				var observe func() error
				switch engine {
				case "proxy":
					f := newInactiveFixture(t, "mihomo")
					root = f.proof.procRoot
					observe = func() error { return proxyInactiveProc(ctx, f.proof, f.a) }
				case "dns":
					f := newScopedDNSInactiveFixture(t)
					root = f.proof.procRoot
					observe = func() error {
						return scopedDNSInactiveProc(ctx, f.proof, f.a.StateRoot, f.a.InactivitySettingsPath, nil)
					}
				case "nfq":
					f := newNFQWS2InactiveFixture(t)
					root = f.proof.procRoot
					observe = func() error { return nfqws2InactiveProcesses(ctx, f.proof, f.a) }
				}
				inactiveWrite(t, filepath.Join(root, "777", "stat"), inactiveReaderStat(777, tc.state, tc.threads, "19"))
				if err := observe(); (err == nil) != tc.accept {
					t.Fatal("terminal caller", err)
				}
			})
		}
	}
}

func TestInactiveProcNFQExemptAndKnownNamesStayClosed(t *testing.T) {
	for _, cut := range []string{"known-z1", "except-z1", "except-gone", "self-z1", "live-except"} {
		t.Run(cut, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			pid := 102
			except := 0
			calls := 0
			f.process(t, pid, "unrelated", 'S', 0, "unrelated\x00")
			switch cut {
			case "known-z1":
				f.process(t, pid, "nfqws2", 'Z', 0, "")
			case "except-z1":
				except = pid
				f.process(t, pid, "unrelated", 'Z', 0, "")
			case "except-gone":
				except = 103
			case "self-z1":
				f.process(t, f.proof.selfPID, "controller", 'Z', 0, "")
			case "live-except":
				except = pid
			}
			err := nfqws2InactiveProcessesExcept(context.Background(), f.proof, f.a, except, func() error { calls++; return nil })
			if (err == nil) != (cut == "live-except") {
				t.Fatal("exemption/name fence", err)
			}
			if cut == "live-except" && calls != 1 || cut == "except-z1" && calls != 0 {
				t.Fatal("owner callback ordering", calls)
			}
		})
	}
}

func TestInactiveProcMissingFactoryNeverUsesModel(t *testing.T) {
	f := newInactiveFixture(t, "mihomo")
	f.proof.procPass = nil
	if proxyInactiveProc(context.Background(), f.proof, f.a) == nil {
		t.Fatal("proxy missing factory")
	}
	d := newScopedDNSInactiveFixture(t)
	d.proof.procPass = nil
	if scopedDNSInactiveProc(context.Background(), d.proof, d.a.StateRoot, d.a.InactivitySettingsPath, nil) == nil {
		t.Fatal("DNS missing factory")
	}
	n := newNFQWS2InactiveFixture(t)
	n.proof.procPass = nil
	if nfqws2InactiveProcesses(context.Background(), n.proof, n.a) == nil {
		t.Fatal("NFQ missing factory")
	}
}

func TestInactiveProcCallerClosingTerminalTransition(t *testing.T) {
	for _, engine := range []string{"proxy", "dns", "nfq"} {
		for _, cut := range []string{"z1", "z2", "X", "x", "known-nfq-z1", "cancel"} {
			t.Run(engine+"/"+cut, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var root string
				var observe func() error
				var setLink func(func(string) (string, error))
				switch engine {
				case "proxy":
					f := newInactiveFixture(t, "mihomo")
					root = f.proof.procRoot
					observe = func() error { return proxyInactiveProc(ctx, f.proof, f.a) }
					setLink = func(link func(string) (string, error)) { f.proof.readlink = link }
				case "dns":
					f := newScopedDNSInactiveFixture(t)
					root = f.proof.procRoot
					observe = func() error {
						return scopedDNSInactiveProc(ctx, f.proof, f.a.StateRoot, f.a.InactivitySettingsPath, nil)
					}
					setLink = func(link func(string) (string, error)) { f.proof.readlink = link }
				case "nfq":
					f := newNFQWS2InactiveFixture(t)
					root = f.proof.procRoot
					observe = func() error { return nfqws2InactiveProcesses(ctx, f.proof, f.a) }
					setLink = func(link func(string) (string, error)) { f.proof.readlink = link }
				}
				path := filepath.Join(root, "777")
				inactiveWrite(t, filepath.Join(path, "stat"), inactiveReaderStat(777, 'S', "1", "19"))
				inactiveWrite(t, filepath.Join(path, "cmdline"), []byte("unrelated\x00"))
				setLink(func(name string) (string, error) {
					if name != filepath.Join(path, "exe") {
						return "/opt/bin/controller", nil
					}
					state := byte('Z')
					threads := "1"
					if cut == "z2" {
						threads = "2"
					}
					if cut == "X" {
						state = 'X'
					}
					if cut == "x" {
						state = 'x'
					}
					raw := inactiveReaderStat(777, state, threads, "19")
					if cut == "known-nfq-z1" {
						raw = []byte(strings.Replace(string(raw), "(fixture)", "(nfqws2)", 1))
					}
					inactiveWrite(t, filepath.Join(path, "stat"), raw)
					if cut == "cancel" {
						cancel()
					}
					return "/opt/bin/unrelated", nil
				})
				err := observe()
				accept := cut == "z1" || cut == "known-nfq-z1" && engine != "nfq"
				if (err == nil) != accept {
					t.Fatal("closing terminal transition", err)
				}
			})
		}
	}
}
