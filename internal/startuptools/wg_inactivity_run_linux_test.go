//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const wgInactivityChildAlias = "wg-inactivity-read-child"

// Only the private test binary's held-FD incarnation uses this argv[0]. The
// child models IP diagnostic bytes, not a native tool, kernel absence or issuer.
func init() {
	if filepath.Base(os.Args[0]) != wgInactivityChildAlias {
		return
	}
	if len(os.Args) != 8 || !slices.Equal(os.Args[1:7], []string{"-N", "-6", "-j", "route", "show", "table"}) ||
		!slices.Contains([]string{"205", "206", "207"}, os.Args[7]) {
		os.Exit(99)
	}
	root := filepath.Dir(os.Getenv("XTABLES_LIBDIR"))
	if os.WriteFile(filepath.Join(root, "started"), []byte("actual child"), 0600) != nil {
		os.Exit(98)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "release")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(97)
		}
		time.Sleep(5 * time.Millisecond)
	}
	fmt.Fprint(os.Stdout, "[]\n")
	if os.Args[7] != "205" {
		fmt.Fprint(os.Stderr, "Error: unexpected readonly failure.\n")
		if os.Args[7] == "207" {
			os.Exit(0)
		}
		os.Exit(3)
	}
	fmt.Fprint(os.Stderr, "Error: ipv6: FIB table does not exist.\nDump terminated\n")
	os.Exit(2)
}

func wgInactivityHeldChildFixture(t *testing.T) (*Lease, string) {
	t.Helper()
	root := t.TempDir()
	extension := filepath.Join(root, "extensions")
	if err := os.Mkdir(extension, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, wgInactivityChildAlias)
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	clear(data)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hash, err := hashImage(ctx, file, info.Size())
	if err != nil {
		file.Close()
		t.Fatal("actual test image must satisfy the existing image bound", err)
	}
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(ctx)
	if err != nil {
		file.Close()
		t.Fatal("opted-in actual ProcProvider unavailable", err)
	}
	p := wgProfile(false, managedListWGProfile)
	p.ipAlias, p.extension = path, extension
	extensionInfo, err := os.Lstat(extension)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	image := &heldImage{path: path, file: file, info: info, hash: hash}
	lifetime, closeLifetime := context.WithCancel(context.Background())
	// Test-private carrier: real original image FD, hash, directory and
	// ProcProvider. This deliberately does not call or validate a factory.
	l := &Lease{provider: provider, identity: identity, profile: p,
		review: &heldReview{profile: p, images: map[string]*heldImage{path: image}, nodes: map[string]heldNode{extension: {path: extension, info: extensionInfo}}, ipEntry: image},
		digest: "private-child-model", lifetime: lifetime, cancel: closeLifetime, gate: make(chan struct{}, 1), closeDone: make(chan struct{})}
	l.gate <- struct{}{}
	t.Cleanup(func() { _ = l.Close() })
	return l, root
}

// Root alone runs this opt-in Linux child test. It proves the real producer's
// Start/Wait/gates and actual file closure with modeled CLI bytes; no IP command
// or WG/kernel/Manager inactivity factory is exercised.
func TestWGInactivityReadHeldChildDiagnostics(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_INACTIVITY_READ_CHILD") != "1" {
		t.Skip("Root actual held-child producer fixture opt-in disabled")
	}
	for _, producer := range []string{"negative-source", "original-wg"} {
		for _, mode := range []string{"current", "unexpected-exit", "stderr-success", "changed-image", "cancelled", "lease-close", "post-start-refusal"} {
			t.Run(producer+"/"+mode, func(t *testing.T) {
				l, root := wgInactivityHeldChildFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				refusal := errors.New("private admission post-Start refusal")
				calls := 0
				owner := admissionFunc(func(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
					calls++
					select {
					case token := <-l.gate:
						l.gate <- token
						return errors.New("Start did not hold the tool gate")
					default:
					}
					if err := begin(); err != nil {
						return err
					}
					if mode == "post-start-refusal" {
						return refusal
					}
					return nil
				})
				type result struct {
					data []byte
					err  error
				}
				done := make(chan result, 1)
				go func() {
					table := "205"
					if mode == "unexpected-exit" {
						table = "206"
					}
					if mode == "stderr-success" {
						table = "207"
					}
					args := []string{"-N", "-6", "-j", "route", "show", "table", table}
					c := WithCommandAdmission(ctx, owner)
					var data []byte
					var err error
					if producer == "original-wg" {
						data, err = l.runWG(c, "wireguard", l.profile.ipAlias, args...)
					} else {
						data, err = l.runWGInactivity(c, l.profile.ipAlias, args...)
					}
					done <- result{data, err}
				}()
				var closeDone chan error
				if mode != "post-start-refusal" {
					deadline := time.Now().Add(3 * time.Second)
					for {
						if _, err := os.Stat(filepath.Join(root, "started")); err == nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("actual child did not start")
						}
						time.Sleep(5 * time.Millisecond)
					}
					probe, closeProbe := context.WithTimeout(ctx, 250*time.Millisecond)
					err := l.lock(probe)
					closeProbe()
					if err != nil {
						t.Fatal("actual child Wait retained the tool gate", err)
					}
					l.unlock()
					switch mode {
					case "cancelled":
						cancel()
					case "lease-close":
						closeDone = make(chan error, 1)
						go func() { closeDone <- l.Close() }()
					case "changed-image":
						if err := os.Rename(l.profile.ipAlias, l.profile.ipAlias+"-original"); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(l.profile.ipAlias, []byte("foreign image"), 0700); err != nil {
							t.Fatal(err)
						}
					}
					if mode == "current" || mode == "unexpected-exit" || mode == "stderr-success" || mode == "changed-image" {
						if err := os.WriteFile(filepath.Join(root, "release"), []byte("finish"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				select {
				case got := <-done:
					if calls != 1 || got.err == nil {
						t.Fatal("actual one-use admission/command failure lost", calls, got.err)
					}
					if mode == "current" {
						want := "[]\nError: ipv6: FIB table does not exist.\nDump terminated\n"
						if string(got.data) != want {
							t.Fatal("actual held-FD producer discarded the bounded diagnostic", got.err)
						}
					} else if mode == "unexpected-exit" {
						if string(got.data) != "[]\nError: unexpected readonly failure.\n" {
							t.Fatal("unexpected errored read changed into FIB absence", got.err)
						}
					} else if len(got.data) != 0 {
						t.Fatal("changed/cancelled source supplied a diagnostic")
					}
					if mode == "post-start-refusal" && !errors.Is(got.err, refusal) {
						t.Fatal("original admission refusal lost", got.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("actual child was not cancelled/joined")
				}
				if closeDone != nil {
					select {
					case err := <-closeDone:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("lease Close did not join the actual retained child")
					}
				}
			})
		}
	}
}

// Root's separate native opt-in uses the real compiled tool lease, Provider
// and control Start bracket. Table 219 must be unused in that fixture. This
// proves diagnostic transport only, never complete runtime inactivity.
func TestProductionWGReadonlyFIBDiagnosticNative(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_INACTIVITY_FIB_NATIVE") != "1" {
		t.Skip("Root genuine IP FIB diagnostic fixture opt-in disabled")
	}
	mode := os.Getenv("RAZVILKA_STARTUP_TOOLS_NATIVE")
	if mode != "ubuntu-legacy" && mode != "stock-nc1812" {
		t.Fatal("explicit existing compiled profile required")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup, closeSetup := context.WithTimeout(lifetime, operationTimeout)
	provider := nativeProvider(t, setup, mode)
	closeSetup()
	l, err := acquireWG(lifetime, provider, wgProfile(mode == "stock-nc1812", managedListWGProfile))
	if err != nil {
		t.Fatal("actual compiled lease acquisition refused: stages=", nativeStages(err))
	}
	defer l.Close()
	ctx, closeCtx := context.WithTimeout(lifetime, 12*time.Second)
	defer closeCtx()
	gate := &operationgate.Gate{}
	original, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	root := t.TempDir()
	if _, err := operationgate.InitializeSelfUpdateControl(original, root); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(original, root)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	args := []string{"-N", "-6", "-j", "route", "show", "table", "219"}
	calls := 0
	owner := admissionFunc(func(c context.Context, name string, actual []string, digest string, begin func() error) error {
		calls++
		if name != l.profile.ipAlias || digest != l.digest || !slices.Equal(actual, args) {
			return errors.New("native fixed read invocation changed")
		}
		return control.WithStart(c, begin)
	})
	for _, producer := range []string{"original-wg", "negative-source"} {
		c := WithCommandAdmission(original, owner)
		var data []byte
		if producer == "original-wg" {
			data, err = l.runWG(c, "wireguard", l.profile.ipAlias, args...)
		} else {
			data, err = l.runWGInactivity(c, l.profile.ipAlias, args...)
		}
		if err == nil || !strings.Contains(string(data), "Error: ipv6: FIB table does not exist.") {
			t.Fatalf("genuine FIB diagnostic not exercised/preserved: producer=%s stages=%s bytes=%d", producer, nativeStages(err), len(data))
		}
	}
	if calls != 2 || control.Current(original) != nil {
		t.Fatal("original control/source read admission changed")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
