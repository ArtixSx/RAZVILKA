//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func staticFactNativeLease(t *testing.T, ctx context.Context) *Lease {
	t.Helper()
	if os.Getenv("RAZVILKA_MANAGED_PROBE_NATIVE") != "1" {
		t.Skip("explicit disposable native fixture only")
	}
	net, ne := os.Readlink("/proc/self/ns/net")
	hostNet, hne := os.Readlink("/proc/1/ns/net")
	mnt, me := os.Readlink("/proc/self/ns/mnt")
	hostMnt, hme := os.Readlink("/proc/1/ns/mnt")
	opt, oe := os.Stat("/opt")
	hostOpt, hoe := os.Stat("/proc/1/root/opt")
	if os.Geteuid() != 0 || ne != nil || hne != nil || me != nil || hme != nil || oe != nil || hoe != nil || net == hostNet || mnt == hostMnt || os.SameFile(opt, hostOpt) {
		t.Fatal("actual disposable mount/network namespaces required")
	}
	l, err := AcquireNativeFixturePolicy(ctx, netidentity.NewProcProvider(), os.Getenv("RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW"))
	if err != nil {
		t.Fatal("actual protected tool producer", nativeStages(err))
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	return l
}

func staticChildrenDelta(l *Lease, before [3]uint64) [3]uint64 {
	after := NativeFixtureVersionChildCount(l)
	for i := range after {
		after[i] -= before[i]
	}
	return after
}

func TestStaticVersionFactNativeScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	foreign := staticFactNativeLease(t, ctx)
	var escaped context.Context
	for pass := 0; pass < 2; pass++ {
		err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
			escaped = observed
			for check, want := range [][3]uint64{{1, 1, 1}, {0, 0, 1}} {
				before := NativeFixtureVersionChildCount(l)
				if err := l.Check(observed, l.identity); err != nil {
					return err
				}
				if got := staticChildrenDelta(l, before); got != want {
					return fmt.Errorf("scope %d check %d child Starts %v, want %v", pass, check, got, want)
				}
			}
			// Nested genuine scopes share the same owner; foreign/copy markers
			// cannot replace its fact with an independently usable authority.
			return l.WithReadOnlyToolObservation(observed, l.identity, l.digest, func(nested context.Context) error {
				if err := foreign.Check(nested, foreign.identity); !errors.Is(err, ErrUnknown) {
					return fmt.Errorf("foreign source accepted original marker: %v", err)
				}
				before := NativeFixtureVersionChildCount(l)
				if err := l.Check(nested, l.identity); err != nil {
					return err
				}
				if got := staticChildrenDelta(l, before); got != [3]uint64{0, 0, 1} {
					return fmt.Errorf("nested child Starts %v", got)
				}
				original, _ := readObservationMarker(nested)
				copied := &toolReadObservation{self: original, lease: l, review: original.review, identity: original.identity, digest: original.digest, ctx: original.ctx, deadline: original.deadline, active: true}
				if err := l.Check(context.WithValue(nested, toolReadObservationKey{}, copied), l.identity); !errors.Is(err, ErrUnknown) {
					return fmt.Errorf("copied scope accepted: %v", err)
				}
				return nil
			})
		})
		if err != nil {
			t.Fatal(nativeStages(err), err)
		}
		if err := l.Check(escaped, l.identity); !errors.Is(err, ErrUnknown) {
			t.Fatal("expired scope accepted", err)
		}
	}
	t.Log("actual first/fresh scope aliases=2 IP=1; repeated/nested aliases=0 IP=1; copied/expired refused")
}

// The filter is installed ONLY on this disposable locked test thread. It does
// not alter the reviewed images/profile or inject a production command hook.
// The thread exits without UnlockOSThread, so Go destroys it with its filter.
func denyNativeVersionForkOnThisThread() error {
	const (
		loadWordAbsolute = 0x20
		jumpEqual        = 0x15
		returnConstant   = 0x06
		allow            = 0x7fff0000
		deny             = 0x00050000 | uint32(syscall.EAGAIN)
	)
	filter := []syscall.SockFilter{
		{Code: loadWordAbsolute, K: 4},          // seccomp_data.arch
		{Code: jumpEqual, K: 0xc000003e, Jt: 1}, // AUDIT_ARCH_X86_64
		{Code: returnConstant, K: 0x80000000},
		{Code: loadWordAbsolute, K: 0},
	}
	for _, number := range []uint32{syscall.SYS_CLONE, 435 /* clone3 */, syscall.SYS_FORK, syscall.SYS_VFORK} {
		filter = append(filter, syscall.SockFilter{Code: jumpEqual, K: number, Jf: 1}, syscall.SockFilter{Code: returnConstant, K: deny})
	}
	filter = append(filter, syscall.SockFilter{Code: returnConstant, K: allow})
	program := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 38 /* NO_NEW_PRIVS */, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 22 /* SET_SECCOMP */, 2 /* FILTER, no TSYNC */, uintptr(unsafe.Pointer(&program)), 0, 0, 0)
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	return nil
}

func TestStaticVersionFactNativeFailedIPClearsFact(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	request := make(chan context.Context, 1)
	ready := make(chan struct{})
	recovered := make(chan error, 1)
	confirmed := make(chan struct{})
	workerDone := make(chan struct{})
	// Prelaunch the unfiltered recovery thread before installing any filter.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(workerDone)
		close(ready)
		select {
		case observed := <-request:
			before := NativeFixtureVersionChildCount(l)
			err := l.Check(observed, l.identity)
			if got := staticChildrenDelta(l, before); got != [3]uint64{1, 1, 1} {
				err = errors.Join(err, fmt.Errorf("recovery did not rerun full actual batch: %v", got))
			}
			recovered <- err
		case <-ctx.Done():
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("unfiltered recovery worker did not become ready", ctx.Err())
	}
	finished := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // Never unlock this filtered thread.
		finished <- l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
			before := NativeFixtureVersionChildCount(l)
			if err := l.Check(observed, l.identity); err != nil {
				return err
			}
			if got := staticChildrenDelta(l, before); got != [3]uint64{1, 1, 1} {
				return fmt.Errorf("initial real batch Starts %v", got)
			}
			if err := denyNativeVersionForkOnThisThread(); err != nil {
				return fmt.Errorf("install thread-only negative filter: %w", err)
			}
			before = NativeFixtureVersionChildCount(l)
			failed := l.Check(observed, l.identity)
			var leaf *failure
			if !errors.Is(failed, syscall.EAGAIN) || !errors.As(failed, &leaf) || leaf.stage != "IP_VERSION" {
				return fmt.Errorf("expected actual IP Start EAGAIN, got %w", failed)
			}
			if got := staticChildrenDelta(l, before); got != [3]uint64{} {
				return fmt.Errorf("failed Start unexpectedly ran children %v", got)
			}
			if err := l.lock(observed); err != nil {
				return errors.Join(failed, err)
			}
			retained := l.versionFact != nil
			l.unlock()
			if retained {
				return errors.Join(failed, errors.New("failed IP retained static fact"))
			}
			select {
			case request <- observed:
			case <-ctx.Done():
				return errors.Join(failed, ctx.Err())
			}
			select {
			case err := <-recovered:
				if err != nil {
					return errors.Join(failed, err)
				}
				close(confirmed)
			case <-ctx.Done():
				return errors.Join(failed, ctx.Err())
			}
			// Preserve the original subprocess exception through scope closing.
			return failed
		})
	}()
	var result error
	select {
	case result = <-finished:
	case <-ctx.Done():
		t.Fatal("filtered owner did not join", ctx.Err())
	}
	cancel()
	select {
	case <-workerDone:
	case <-time.After(operationTimeout):
		t.Fatal("unfiltered recovery worker did not join")
	}
	if !errors.Is(result, syscall.EAGAIN) {
		t.Fatal("original IP exception lost", nativeStages(result), result)
	}
	select {
	case <-confirmed:
	default:
		t.Fatal("no successful actual full recovery batch", result)
	}
	// An unexpected earlier failure must not be mistaken for the expected IP
	// failure: the actual recovery worker must have received and run its batch.
	if got := NativeFixtureVersionChildCount(l); got != [3]uint64{2, 2, 2} {
		t.Fatal("actual initial/recovery Start totals", got, result)
	}
	t.Log("actual IP Start EAGAIN cleared retained fact; unfiltered original scope reran both aliases and IP; original exception preserved")
}

func TestStaticVersionFactNativePartialBatchNeverRetained(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
		original := l.profile.ipVersion
		l.profile.ipVersion = "deliberately wrong expected IP version, never a native grant"
		before := NativeFixtureVersionChildCount(l)
		failed := l.Check(observed, l.identity)
		l.profile.ipVersion = original
		var leaf *failure
		if !errors.As(failed, &leaf) || leaf.stage != "IP_VERSION" {
			return fmt.Errorf("actual partial batch did not fail its IP output: %w", failed)
		}
		if got := staticChildrenDelta(l, before); got != [3]uint64{1, 1, 1} {
			return fmt.Errorf("partial batch did not execute all actual children: %v", got)
		}
		if l.versionFact != nil {
			return errors.New("partial batch retained version fact")
		}
		before = NativeFixtureVersionChildCount(l)
		if err := l.Check(observed, l.identity); err != nil {
			return err
		}
		if got := staticChildrenDelta(l, before); got != [3]uint64{1, 1, 1} {
			return fmt.Errorf("retry reused partial batch: %v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(nativeStages(err), err)
	}
}

func TestStaticVersionFactNativeOriginalFingerprint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	for _, corrupt := range []func(*scopedVersionFact){
		func(f *scopedVersionFact) { f.self = nil },
		func(f *scopedVersionFact) { f.environment[0] += "-changed" },
		func(f *scopedVersionFact) { f.profile.ipVersion += "-changed" },
		func(f *scopedVersionFact) { f.entry[0] = nil },
	} {
		err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
			if err := l.Check(observed, l.identity); err != nil {
				return err
			}
			if err := l.lock(observed); err != nil {
				return err
			}
			fact := l.versionFact
			if fact != nil {
				corrupt(fact)
			}
			l.unlock()
			if fact == nil {
				return errors.New("genuine complete version batch did not issue a fact")
			}
			before := NativeFixtureVersionChildCount(l)
			failed := l.Check(observed, l.identity)
			var leaf *failure
			if !errors.As(failed, &leaf) || leaf.stage != "VERSION_FACT_CHANGED" {
				return fmt.Errorf("changed original fact accepted: %w", failed)
			}
			if got := staticChildrenDelta(l, before); got != [3]uint64{} {
				return fmt.Errorf("changed fact ran children: %v", got)
			}
			if l.versionFact != nil {
				return errors.New("changed fact survived failed Check")
			}
			before = NativeFixtureVersionChildCount(l)
			if err := l.Check(observed, l.identity); err != nil {
				return err
			}
			if got := staticChildrenDelta(l, before); got != [3]uint64{1, 1, 1} {
				return fmt.Errorf("changed fact retry did not reexecute full batch: %v", got)
			}
			return nil
		})
		if err != nil {
			t.Fatal(nativeStages(err), err)
		}
	}
}
