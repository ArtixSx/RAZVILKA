//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Deliberately expose only the previous original reader for paired sampling.
// All calls still use the SAME Lease, Provider, source review and namespace.
type classicSaveNativeSerial struct{ l *Lease }

func (r classicSaveNativeSerial) Run(c context.Context, n string, a ...string) ([]byte, error) {
	return r.l.Run(c, n, a...)
}
func (r classicSaveNativeSerial) RunBounded(c context.Context, n string, b int, a ...string) ([]byte, error) {
	return r.l.RunBounded(c, n, b, a...)
}
func (r classicSaveNativeSerial) ReadBoundedClassicTables(c context.Context, id netidentity.Identity, rev string, p [2]string, b int, t [2][]string) ([2][][]byte, error) {
	return r.l.ReadBoundedClassicTables(c, id, rev, p, b, t)
}

func TestClassicSaveNativeInventoryParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	if !l.classicSaveSupported() {
		t.Fatal("actual reviewed fixture must exercise save ABI")
	}
	// Fixed inert chains in every registered classic table, with escaped
	// comments and an empty chain; no hooks or traffic-policy changes.
	for _, path := range l.profile.aliases {
		for _, table := range []string{"filter", "mangle", "nat", "raw", "security"} {
			for _, chain := range []string{"RZV_SAVE_EQ", "RZV_SAVE_EMPTY"} {
				if data, err := exec.CommandContext(ctx, path, "-t", table, "-N", chain).CombinedOutput(); err != nil {
					t.Fatal("isolated parity chain setup", err, string(data))
				}
				// Register cleanup as soon as this exact chain is created. A
				// later setup failure never deletes a pre-existing foreign chain.
				defer func() {
					for _, op := range []string{"-F", "-X"} {
						c, stop := context.WithTimeout(context.Background(), 2*time.Second)
						data, err := exec.CommandContext(c, path, "-t", table, op, chain).CombinedOutput()
						stop()
						if err != nil {
							t.Error("isolated parity cleanup", err, string(data))
						}
					}
				}()
			}
			for _, args := range [][]string{{"-t", table, "-A", "RZV_SAVE_EQ", "-p", "tcp", "--dport", "443", "-m", "comment", "--comment", "quote \" slash \\ space", "-j", "RETURN"}, {"-t", table, "-A", "RZV_SAVE_EQ", "-p", "udp", "--dport", "53", "-j", "DROP"}} {
				if data, err := exec.CommandContext(ctx, path, args...).CombinedOutput(); err != nil {
					t.Fatal("isolated parity rule setup", err, string(data))
				}
			}
		}
	}
	tools, err := l.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	fast, err := dataplane.NewBackendInventory(l.provider, tools)
	if err != nil {
		t.Fatal(err)
	}
	tools.Runner = classicSaveNativeSerial{l}
	serial, err := dataplane.NewBackendInventory(l.provider, tools)
	if err != nil {
		t.Fatal(err)
	}
	err = l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
		for sample := range 6 {
			var images [2]dataplane.BackendInventorySnapshot
			var elapsed [2]time.Duration
			var metadata [2]uint64
			var children [2]map[string]int64
			for index, inventory := range []*dataplane.BackendInventory{serial, fast} {
				before := NativeFixtureVersionMetadataCount(l)
				stop := StartDomainNativeToolMeasurement()
				started := time.Now()
				images[index], err = inventory.Read(observed, l.identity)
				elapsed[index] = time.Since(started)
				children[index] = stop()
				metadata[index] = NativeFixtureVersionMetadataCount(l) - before
				if err != nil || images[index].RequireComplete() != nil {
					return errors.Join(err, images[index].RequireComplete())
				}
			}
			if !reflect.DeepEqual(images[0].Rows, images[1].Rows) {
				t.Fatal("actual -S/save complete rows differ")
			}
			if children[0]["original-read-classic-batch"] != 20 || children[0]["original-read-classic-save"] != 0 || children[1]["original-read-classic-save"] != 4 || children[1]["original-read-classic-batch"] != 0 {
				t.Fatal("actual producer/fallback witness", children)
			}
			t.Logf("classic_save_actual sample=%d serial_ms=%.3f save_ms=%.3f serial_metadata=%d save_metadata=%d serial_children=20 save_children=4 equal_rows=%d", sample, float64(elapsed[0].Microseconds())/1000, float64(elapsed[1].Microseconds())/1000, metadata[0], metadata[1], len(images[0].Rows))
		}
		return nil
	})
	if err != nil {
		t.Fatal("actual protected full-inventory parity", nativeStages(err))
	}
}

func TestClassicSaveNativeLockCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx) // Checks disposable mount/network scope.
	classicSaveNativePrivateMounts(t)
	// Shadow only this namespace's lock inode; never rename/unlink the original.
	target, err := os.OpenFile(classicSaveLockPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	target.Close()
	for _, kind := range []string{"busy", "replacement", "cancelled", "fresh"} {
		t.Run(kind, func(t *testing.T) {
			file, err := os.CreateTemp("/var/lib", "razvilka-save-lock-")
			if err != nil {
				t.Fatal(err)
			}
			path := file.Name()
			file.Close()
			defer os.Remove(path)
			if err := syscall.Mount(path, classicSaveLockPath, "", syscall.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			defer syscall.Unmount(classicSaveLockPath, 0)
			lock, err := openClassicSaveLock(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.close()
			if kind == "replacement" {
				other, err := os.CreateTemp("/var/lib", "razvilka-save-replacement-")
				if err != nil {
					t.Fatal(err)
				}
				replacement := other.Name()
				other.Close()
				defer os.Remove(replacement)
				if err := syscall.Mount(replacement, classicSaveLockPath, "", syscall.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
				if lock.current(ctx) == nil {
					t.Error("retained lock adopted replacement")
				}
				if err := syscall.Unmount(classicSaveLockPath, 0); err != nil {
					t.Fatal(err)
				}
				if err := lock.current(ctx); err != nil {
					t.Fatal("original lock did not recover after unmount", err)
				}
				return
			}
			if kind == "busy" {
				data, err := exec.CommandContext(ctx, l.profile.aliases[0], "-t", "mangle", "-S").CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 4 || !strings.Contains(string(data), "lock") {
					t.Fatal("parent does not hold SAME actual xtables lock", err, string(data))
				}
			} else {
				if err := lock.close(); err != nil {
					t.Fatal(err)
				}
			}
			leaf, stop := context.WithCancel(ctx)
			defer stop()
			if kind == "cancelled" {
				stop()
			}
			measure := StartDomainNativeToolMeasurement()
			_, supported, readErr := l.ReadBoundedClassicInventory(leaf, l.identity, l.digest, l.profile.aliases, 1<<20, [2][]string{{"mangle"}, {"mangle"}})
			counts := measure()
			if !supported {
				t.Fatal("native path silently fell back")
			}
			if kind == "fresh" {
				if readErr != nil || counts["original-read-classic-save"] != 2 {
					t.Fatal("fresh lock/read failed", nativeStages(readErr), counts)
				}
			} else if readErr == nil || counts["original-read-classic-save"] != 0 {
				t.Fatal("failed lock/cancel still issued child", readErr, counts)
			}
			if kind == "cancelled" && !errors.Is(readErr, context.Canceled) {
				t.Fatal("cancel cause lost", readErr)
			}
		})
	}
	// The stock profile has no new save authority even on this host.
	if stockProfile().classicSaveABI || slices.Equal(stockProfile().aliases, l.profile.aliases) {
		t.Fatal("stock fallback profile changed")
	}
}

// A distinct mount namespace alone can still propagate bind mounts to its
// parent. Prove the actual root propagation before any lock fixture mount.
func classicSaveNativePrivateMounts(t *testing.T) {
	t.Helper()
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 1<<20 {
		t.Fatal("bounded mount propagation", readErr, closeErr)
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[4] != "/" && f[4] != "/run" && f[4] != classicSaveLockPath {
			continue
		}
		found = found || f[4] == "/"
		for _, field := range f[6:] {
			if field == "-" {
				break
			}
			if strings.HasPrefix(field, "shared:") || strings.HasPrefix(field, "master:") || strings.HasPrefix(field, "propagate_from:") {
				t.Fatal("lock bind fixture requires private root propagation")
			}
		}
	}
	if !found {
		t.Fatal("root mount propagation unavailable")
	}
}
