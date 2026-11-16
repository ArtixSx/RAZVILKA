//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// Ordinary-file classification model only. Actual fd/mount and thread-group
// behavior is checked separately by the isolated native reproduction.
func inactiveReaderLinuxFixture(t *testing.T, state byte, threads string) (*modelInactiveProcPID, string) {
	t.Helper()
	root := t.TempDir()
	pid := 102
	path := filepath.Join(root, strconv.Itoa(pid))
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "stat"), inactiveReaderStat(pid, state, threads, "17"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &modelInactiveProcPass{ctx: context.Background(), root: root, self: 101}
	child, err := p.OpenPID(pid)
	if err != nil {
		t.Fatal(err)
	}
	h := child.(*modelInactiveProcPID)
	t.Cleanup(func() {
		if !h.closed {
			_ = h.Close()
		}
		if !p.closed {
			_ = p.Close()
		}
	})
	return h, path
}
func TestInactiveProcHeldTerminalStates(t *testing.T) {
	for _, tc := range []struct {
		name             string
		state            byte
		threads          string
		readOK, terminal bool
	}{
		{"zombie-single", 'Z', "1", true, true}, {"zombie-worker", 'Z', "2", true, false}, {"dead-X", 'X', "1", true, false}, {"dead-x", 'x', "1", true, false}, {"live", 'S', "1", true, false}, {"zero", 'Z', "0", false, false}, {"leading-zero", 'Z', "01", false, false}, {"unknown", '?', "1", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := inactiveReaderLinuxFixture(t, tc.state, tc.threads)
			_, err := h.Stat()
			if (err == nil) != tc.readOK {
				t.Fatal(err)
			}
			if h.Terminal() != tc.terminal {
				t.Fatal("terminal classification")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInactiveProcHeldTerminalDrift(t *testing.T) {
	for _, cut := range []string{"live", "worker", "birth", "replace", "malformed", "missing-stat", "copied", "cancelled", "self"} {
		t.Run(cut, func(t *testing.T) {
			h, path := inactiveReaderLinuxFixture(t, 'Z', "1")
			if _, err := h.Stat(); err != nil {
				t.Fatal(err)
			}
			write := func(raw []byte) {
				if err := os.WriteFile(filepath.Join(path, "stat"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch cut {
			case "live":
				write(inactiveReaderStat(h.pid, 'S', "1", "17"))
			case "worker":
				write(inactiveReaderStat(h.pid, 'Z', "2", "17"))
			case "birth":
				write(inactiveReaderStat(h.pid, 'Z', "1", "18"))
			case "replace":
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				write(inactiveReaderStat(h.pid, 'Z', "1", "17"))
			case "malformed":
				write([]byte("invalid"))
			case "missing-stat":
				if err := os.Remove(filepath.Join(path, "stat")); err != nil {
					t.Fatal(err)
				}
			case "copied":
				copy := *h
				if copy.Terminal() {
					t.Fatal("copied handle admitted")
				}
				return
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				h.pass.ctx = ctx
				cancel()
			case "self":
				h.pass.self = h.pid
			}
			if h.Terminal() {
				t.Fatal("drift admitted")
			}
		})
	}
}

func TestInactiveProcHeldTerminalClosingAndGone(t *testing.T) {
	t.Run("late-exec", func(t *testing.T) {
		h, path := inactiveReaderLinuxFixture(t, 'Z', "1")
		if _, err := h.Stat(); err != nil {
			t.Fatal(err)
		}
		if !h.Terminal() {
			t.Fatal("terminal opening")
		}
		if err := os.WriteFile(filepath.Join(path, "stat"), inactiveReaderStat(h.pid, 'S', "1", "17"), 0600); err != nil {
			t.Fatal(err)
		}
		if h.Close() == nil {
			t.Fatal("late exec admitted")
		}
	})
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint("gone-replace-", replace), func(t *testing.T) {
			h, path := inactiveReaderLinuxFixture(t, 'S', "1")
			if _, err := h.Stat(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(path, "stat")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if !h.Terminal() {
				t.Fatal("held/named absence refused")
			}
			if replace {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if (h.Close() == nil) == replace {
				t.Fatal("closing name proof")
			}
		})
	}
}

func TestInactiveProcFactoryAndErrorRefusals(t *testing.T) {
	if p, err := openLinuxInactiveProc(context.Background(), t.TempDir(), os.Getpid()); err == nil || p != nil {
		t.Fatal("ordinary tree adopted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := openLinuxInactiveProc(ctx, "/proc", os.Getpid()); err == nil || p != nil {
		t.Fatal("cancelled factory")
	}
	for _, err := range []error{nil, unix.EACCES, unix.EIO, errors.Join(unix.ENOENT, unix.EIO), errors.Join(unix.ESRCH, context.Canceled), ErrProxyRuntimeInactive} {
		if inactiveProcRetireError(err) {
			t.Fatal("error promoted", err)
		}
	}
	for _, err := range []error{unix.ENOENT, unix.ESRCH, errors.Join(ErrProxyRuntimeInactive, unix.ENOENT)} {
		if !inactiveProcRetireError(err) {
			t.Fatal("missing errno lost", err)
		}
	}
}

func TestInactiveProcActualSelfReadOnly(t *testing.T) {
	pass, err := openLinuxInactiveProc(context.Background(), "/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	child, err := pass.OpenPID(os.Getpid())
	if err != nil {
		_ = pass.Close()
		t.Fatal(err)
	}
	_, statErr := child.Stat()
	_, cmdErr := child.Command()
	exe, exeErr := child.Executable()
	terminal := child.Terminal()
	closeErr := errors.Join(child.Close(), pass.Close())
	if statErr != nil || cmdErr != nil || exeErr != nil || exe == "" || terminal || closeErr != nil {
		t.Fatal("actual self read-only proof", statErr, cmdErr, exeErr, terminal, closeErr)
	}
}
