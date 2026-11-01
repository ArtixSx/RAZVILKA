//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Actual protected ELF/FD/source/namespace and literal command execution.
// Platform classification alone uses the existing explicit native fixture.
// All mutations affect private byte copies in this disposable mount namespace.
func TestClassicReadBatchNativeMutation(t *testing.T) {
	if os.Getenv("RAZVILKA_MANAGED_PROBE_NATIVE") != "1" {
		t.Skip("explicit isolated native fixture only")
	}
	for index, kind := range []string{"held-file", "extension-membership", "observation-held-file", "observation-extension-membership", "observation-close"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			net, ne := os.Readlink("/proc/self/ns/net")
			initialNet, ine := os.Readlink("/proc/1/ns/net")
			mnt, me := os.Readlink("/proc/self/ns/mnt")
			initialMnt, ime := os.Readlink("/proc/1/ns/mnt")
			ownOpt, oe := os.Stat("/opt")
			hostOpt, hoe := os.Stat("/proc/1/root/opt")
			if os.Geteuid() != 0 || ne != nil || ine != nil || me != nil || ime != nil || oe != nil || hoe != nil || net == initialNet || mnt == initialMnt || os.SameFile(ownOpt, hostOpt) || ownOpt.Mode().Perm() != 0755 {
				t.Fatal("actual private mount/network fixture required")
			}
			mountFile, err := os.Open("/proc/self/mountinfo")
			if err != nil {
				t.Fatal(err)
			}
			mounts, mountReadErr := io.ReadAll(io.LimitReader(mountFile, (1<<20)+1))
			closeErr := mountFile.Close()
			if mountReadErr != nil || closeErr != nil || len(mounts) > 1<<20 {
				t.Fatal("bounded actual mount inventory", mountReadErr, closeErr)
			}
			privateRoot, tmpfsOpt := false, false
			for _, line := range strings.Split(string(mounts), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 10 {
					continue
				}
				separator := -1
				for i, field := range fields {
					if field == "-" {
						separator = i
						break
					}
				}
				if separator < 6 || separator+1 >= len(fields) {
					continue
				}
				if fields[4] == "/" {
					privateRoot = true
					for _, field := range fields[6:separator] {
						if strings.HasPrefix(field, "shared:") || strings.HasPrefix(field, "master:") || strings.HasPrefix(field, "propagate_from:") {
							privateRoot = false
						}
					}
				}
				if fields[4] == "/opt" && fields[separator+1] == "tmpfs" {
					tmpfsOpt = true
				}
			}
			if !privateRoot || !tmpfsOpt {
				t.Fatal("private propagation and real tmpfs required before bind")
			}
			const extensions = "/usr/lib/x86_64-linux-gnu/xtables"
			copyRoot, err := os.MkdirTemp("/var/lib", "razvilka-classic-native-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(copyRoot)
			private := filepath.Join(copyRoot, "extensions")
			if err := os.Mkdir(private, 0700); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(extensions)
			if err != nil || len(entries) > 256 {
				t.Fatal("actual extension inventory", err)
			}
			bytes := 0
			for _, entry := range entries {
				source, target := filepath.Join(extensions, entry.Name()), filepath.Join(private, entry.Name())
				info, err := os.Lstat(source)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode()&os.ModeSymlink != 0 {
					link, err := os.Readlink(source)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.Symlink(link, target); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if !info.Mode().IsRegular() || info.Size() > maxImageBytes || info.Size() < 0 {
					t.Fatal("unexpected actual extension")
				}
				bytes += int(info.Size())
				if bytes > maxReviewBytes {
					t.Fatal("extension copy bound")
				}
				data, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"libxt_tcp.so", "libxt_comment.so"} {
				info, err := os.Lstat(filepath.Join(private, name))
				if err != nil || !info.Mode().IsRegular() {
					t.Fatal("mutation requires private regular ELF copies", name, err)
				}
			}
			if err := syscall.Mount(private, extensions, "", syscall.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			defer syscall.Unmount(extensions, syscall.MNT_DETACH)
			chain := "RZV_CI_RO_" + strconv.Itoa(index)
			for _, args := range [][]string{{"-t", "mangle", "-N", chain}, {"-t", "mangle", "-A", chain, "-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "RETURN"}} {
				if output, err := exec.CommandContext(ctx, "/usr/sbin/iptables-legacy", args...).CombinedOutput(); err != nil {
					t.Fatal("inert no-hook fixture setup", err, string(output))
				}
			}
			provider := netidentity.NewProcProvider()
			lease, err := AcquireNativeFixturePolicy(ctx, provider, os.Getenv("RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW"))
			if err != nil {
				t.Fatal("actual protected producer", nativeStages(err))
			}
			defer lease.Close()
			if strings.HasPrefix(kind, "observation-") {
				readObservationNativeLifecycle(t, ctx, lease, kind == "observation-close")
				if kind == "observation-close" {
					return
				}
			}
			watch, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Close(watch)
			if _, err := syscall.InotifyAddWatch(watch, filepath.Join(extensions, "libxt_tcp.so"), syscall.IN_OPEN); err != nil {
				t.Fatal(err)
			}
			type mutationResult struct {
				err       error
				completed time.Time
			}
			mutated := make(chan mutationResult, 1)
			go func() {
				complete := func(err error) { mutated <- mutationResult{err: err, completed: time.Now()} }
				var events [4096]byte
				for {
					n, err := syscall.Read(watch, events[:])
					if n > 0 && err == nil {
						break
					}
					if err != nil && !errors.Is(err, syscall.EAGAIN) {
						complete(err)
						return
					}
					select {
					case <-ctx.Done():
						complete(ctx.Err())
						return
					case <-time.After(100 * time.Microsecond):
					}
				}
				if strings.HasSuffix(kind, "held-file") {
					file, err := os.OpenFile(filepath.Join(private, "libxt_comment.so"), os.O_WRONLY|os.O_APPEND, 0)
					if err != nil {
						complete(err)
						return
					}
					_, err = file.Write([]byte{0})
					complete(errors.Join(err, file.Close()))
					return
				}
				// A newly enumerated extension is never loaded by the fixed rule.
				data, err := os.ReadFile(filepath.Join(private, "libxt_comment.so"))
				if err == nil {
					err = os.WriteFile(filepath.Join(private, "libxt_unreviewed_fixture.so"), data, 0600)
				}
				complete(err)
			}()
			var result [2][][]byte
			var readErr error
			read := func(observed context.Context) error {
				var err error
				result, err = lease.ReadBoundedClassicTables(observed, lease.identity, lease.digest, lease.profile.aliases, 1<<20, [2][]string{{"mangle"}, {"mangle"}})
				return err
			}
			if strings.HasPrefix(kind, "observation-") {
				readErr = lease.WithReadOnlyToolObservation(ctx, lease.identity, lease.digest, read)
			} else {
				readErr = read(ctx)
			}
			returned := time.Now()
			mutation := <-mutated
			if mutation.err != nil {
				t.Fatal("actual first literal read did not trigger owned mutation", mutation.err)
			}
			if mutation.completed.After(returned) {
				t.Fatal("late fault injection: fixture did not mutate before the public batch returned; guard not evaluated", readErr)
			}
			stages := nativeStages(readErr)
			if !errors.Is(readErr, ErrUnknown) || len(result[0]) != 0 || len(result[1]) != 0 || !strings.Contains(stages, "CHECK_PATH") && !strings.Contains(stages, "CHECK_HELD_FILE") && !strings.Contains(stages, "CHECK_BYTES") && !strings.Contains(stages, "CHECK_EXTENSION_SET") {
				t.Fatal("changed actual held source issued an image", stages)
			}
			t.Log("actual protected first -S loaded held TCP extension;", kind, "change refused whole image; no hooks or packets, host tools unchanged")
		})
	}
}

// Uses the genuine protected factory source. The callback itself never calls
// Close: its external owner performs shutdown concurrently, as in production.
func readObservationNativeLifecycle(t *testing.T, ctx context.Context, lease *Lease, externalClose bool) {
	t.Helper()
	callbackFailure := errors.New("original native readonly callback failure")
	if externalClose {
		entered := make(chan struct{})
		callbackExited := make(chan struct{})
		finished := make(chan error, 1)
		go func() {
			finished <- lease.WithReadOnlyToolObservation(ctx, lease.identity, lease.digest, func(observed context.Context) error {
				defer close(callbackExited)
				if err := lease.Check(observed, lease.identity); err != nil {
					return err
				}
				close(entered)
				<-observed.Done()
				return callbackFailure
			})
		}()
		select {
		case <-entered:
		case err := <-finished:
			t.Fatal("external Close observation did not start", nativeStages(err))
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if err := lease.Close(); err != nil {
			t.Fatal("original external Close", err)
		}
		if ctx.Err() != nil {
			t.Fatal("parent deadline replaced actual external Close cancellation")
		}
		select {
		case <-callbackExited:
		default:
			t.Fatal("Close released descriptors before original callback finished")
		}
		select {
		case err := <-finished:
			if !errors.Is(err, callbackFailure) || !errors.Is(err, ErrUnknown) {
				t.Fatal("external Close lost callback or invalidated owner", err)
			}
		case <-time.After(operationTimeout):
			t.Fatal("original observation caller did not receive terminal Close error")
		}
		t.Log("actual external original Lease.Close cancelled and joined readonly observation before closing held descriptors")
		return
	}
	var escaped context.Context
	err := lease.WithReadOnlyToolObservation(ctx, lease.identity, lease.digest, func(observed context.Context) error {
		escaped = observed
		metadataBefore := NativeFixtureVersionMetadataCount(lease)
		if err := lease.Check(observed, lease.identity); err != nil {
			return err
		}
		t.Log("native completed scoped three-version Check original metadata traversal attempts", NativeFixtureVersionMetadataCount(lease)-metadataBefore)
		original, _ := readObservationMarker(observed)
		copied := &toolReadObservation{self: original, lease: lease, review: original.review, identity: original.identity, digest: original.digest, ctx: original.ctx, deadline: original.deadline, active: true}
		if err := lease.Check(context.WithValue(observed, toolReadObservationKey{}, copied), lease.identity); !errors.Is(err, ErrUnknown) {
			t.Fatal("copied observation borrowed genuine held source", err)
		}
		for _, source := range []*Lease{lease, new(Lease)} {
			_, err := source.policyEffect(observed, 0, []string{"-t", "mangle", "-N", "RZV_MUST_NOT_CREATE"})
			var refused *failure
			if !errors.As(err, &refused) || refused.stage != "READ_OBSERVATION_EFFECT" {
				t.Fatal("effect entered readonly source", err)
			}
			_, err = source.runWGInactivityHeld(observed, "foreign", []string{"set"}...)
			if !errors.As(err, &refused) || refused.stage != "READ_OBSERVATION_EFFECT" {
				t.Fatal("WG admission entered readonly source", err)
			}
		}
		return callbackFailure
	})
	if !errors.Is(err, callbackFailure) {
		t.Fatal("native callback exception lost", err)
	}
	if err := lease.Check(escaped, lease.identity); !errors.Is(err, ErrUnknown) {
		t.Fatal("late original observation issued facts", err)
	}
	if err := lease.WithReadOnlyToolObservation(escaped, lease.identity, lease.digest, func(context.Context) error { t.Fatal("expired loan invoked callback"); return nil }); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	if err := lease.Check(ctx, lease.identity); err != nil {
		t.Fatal("scope retirement cancelled original owner", nativeStages(err))
	}
	// A genuinely executed fixed --version observation must retain its
	// comparison failure alongside a later actual closing membership change.
	// Only the expected version string is deliberately corrupted; original
	// executable/argv/FD/loader/admission remain the actual protected producer.
	extra := filepath.Join(lease.profile.extension, "rzv-version-close-negative")
	versionErr := lease.WithReadOnlyToolObservation(ctx, lease.identity, lease.digest, func(observed context.Context) error {
		expected := lease.profile.version
		lease.profile.version = expected + "-negative-comparison"
		readErr := lease.Check(observed, lease.identity)
		lease.profile.version = expected
		var failed *failure
		if !errors.As(readErr, &failed) || failed.stage != "BACKEND_VERSION" {
			t.Fatal("actual version observation failure missing", nativeStages(readErr))
		}
		if err := os.WriteFile(extra, []byte("private negative closing membership"), 0600); err != nil {
			t.Fatal(err)
		}
		return readErr
	})
	removeErr := os.Remove(extra)
	if removeErr != nil || !strings.Contains(nativeStages(versionErr), "BACKEND_VERSION") || !strings.Contains(nativeStages(versionErr), "CHECK_EXTENSION_SET") {
		t.Fatal("actual version or closing exception lost", nativeStages(versionErr), removeErr)
	}
	if err := lease.Check(ctx, lease.identity); err != nil {
		t.Fatal("private negative membership removal did not restore original graph", nativeStages(err))
	}
	panicValue := new(int)
	func() {
		defer func() {
			if recovered := recover(); recovered != panicValue {
				t.Fatal("original panic changed", recovered)
			}
		}()
		_ = lease.WithReadOnlyToolObservation(ctx, lease.identity, lease.digest, func(observed context.Context) error { escaped = observed; panic(panicValue) })
	}()
	if err := lease.Check(escaped, lease.identity); !errors.Is(err, ErrUnknown) {
		t.Fatal("panic leaked active readonly context", err)
	}
	if err := lease.Check(ctx, lease.identity); err != nil {
		t.Fatal("panic leaked original tool gate", nativeStages(err))
	}
	// One genuine held read remains active when the callback returns an error.
	// Retirement must cancel it and join its gate borrower before closing SHA.
	entered := make(chan error, 1)
	joined := make(chan struct{}, 1)
	err = lease.WithReadOnlyToolObservation(ctx, lease.identity, lease.digest, func(observed context.Context) error {
		go func() {
			if err := lease.lock(observed); err != nil {
				entered <- err
				return
			}
			err := lease.current(observed, lease.identity, true)
			entered <- err
			<-observed.Done()
			joined <- struct{}{}
			lease.unlock()
		}()
		if err := <-entered; err != nil {
			return err
		}
		return callbackFailure
	})
	if !errors.Is(err, callbackFailure) {
		t.Fatal("joined native read lost callback error", err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("original held native read was not joined")
	}
	if err := lease.Check(ctx, lease.identity); err != nil {
		t.Fatal("joined original source did not remain current", nativeStages(err))
	}
	t.Log("actual original readonly observation: error/panic/late marker/effect rejection and cancellation+held-read join confirmed")
}
