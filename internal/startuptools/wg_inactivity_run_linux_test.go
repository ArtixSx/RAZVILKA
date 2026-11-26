//go:build linux && (amd64 || arm64)

package startuptools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

// An explicit helper selects only the private diagnostic image, never a native
// consumer/service or factory grant. Historical callers retain the self image.
func wgInactivityFixtureImage(t *testing.T) []byte {
	t.Helper()
	path := os.Getenv("RAZVILKA_WG_INACTIVITY_HELPER")
	if path == "" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data, err := readWGInactivityFixtureImage(path)
	if err != nil {
		t.Fatal("explicit private helper refused", err)
	}
	return data
}

func readWGInactivityFixtureImage(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("helper path")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0111 == 0 || before.Size() <= 0 || before.Size() > maxImageBytes {
		return nil, errors.New("helper shape")
	}
	// Do not let a named replacement between Lstat and open turn the private
	// image read into a blocking FIFO or a followed symlink.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		return nil, errors.Join(errors.New("helper file descriptor"), unix.Close(fd))
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(errors.New("helper open identity"), statErr, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxImageBytes+1))
	after, afterErr := file.Stat()
	named, namedErr := os.Lstat(path)
	closeErr := file.Close()
	if err := errors.Join(readErr, afterErr, namedErr, closeErr); err != nil {
		clear(data)
		return nil, err
	}
	same := func(info os.FileInfo) bool {
		return os.SameFile(before, info) && info.Size() == before.Size() && info.Mode() == before.Mode() && info.ModTime() == before.ModTime()
	}
	if int64(len(data)) != before.Size() || !same(after) || !same(named) {
		clear(data)
		return nil, errors.New("helper closing identity")
	}
	return data, nil
}

func wgInactivityHeldChildFixture(t *testing.T) (*Lease, string) {
	t.Helper()
	root := t.TempDir()
	extension := filepath.Join(root, "extensions")
	if err := os.Mkdir(extension, 0700); err != nil {
		t.Fatal(err)
	}
	data := wgInactivityFixtureImage(t)
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
	root := filepath.Join(t.TempDir(), "control")
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

func TestWGInactivityFixtureImageRefusals(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "helper")
	if err := os.WriteFile(valid, []byte("private fixture bytes"), 0700); err != nil {
		t.Fatal(err)
	}
	if data, err := readWGInactivityFixtureImage(valid); err != nil || string(data) != "private fixture bytes" {
		t.Fatal("valid helper read", err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", root, link, fifo, filepath.Join(root, "missing")} {
		if data, err := readWGInactivityFixtureImage(path); err == nil || data != nil {
			t.Fatal("invalid helper accepted", path)
		}
	}
	if err := os.Chmod(valid, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWGInactivityFixtureImage(valid); err == nil {
		t.Fatal("non-executable helper accepted")
	}
	if err := os.Chmod(valid, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(valid, maxImageBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readWGInactivityFixtureImage(valid); err == nil {
		t.Fatal("oversized helper accepted")
	}
	if err := os.Truncate(valid, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readWGInactivityFixtureImage(valid); err == nil {
		t.Fatal("empty helper accepted")
	}
}

func TestWGInactivitySmallHelperABI(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_INACTIVITY_READ_CHILD") != "1" || os.Getenv("RAZVILKA_WG_INACTIVITY_HELPER") == "" {
		t.Skip("explicit small private helper required")
	}
	l, root := wgInactivityHeldChildFixture(t)
	file := l.review.ipEntry.file
	for _, row := range []struct {
		alias  string
		args   []string
		output string
		code   int
	}{
		{"wg-kernel-link-metadata-ip", []string{"-Version"}, ubuntuPolicyProfile().ipVersion, 0},
		{"wg-kernel-link-metadata-iptables", []string{"--version"}, "iptables v" + ubuntuProfile().version + "\n", 0},
		{"wg-kernel-link-metadata-ip6tables", []string{"--version"}, "ip6tables v" + ubuntuProfile().version + "\n", 0},
		{"unknown", []string{"-Version"}, "", 99},
		{"wg-kernel-link-metadata-ip", []string{"-Version", "extra"}, "", 99},
		{"wg-kernel-link-metadata-iptables", []string{"-Version"}, "", 99},
		{"wg-kernel-link-metadata-ip6tables", []string{"-Version"}, "", 99},
		{wgInactivityChildAlias, []string{"-N", "-6", "-j", "route", "show", "table", "999"}, "", 99},
	} {
		t.Run(row.alias+strings.Join(row.args, "-"), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/fd/3", row.args...)
			cmd.Args[0] = row.alias
			cmd.ExtraFiles = []*os.File{file}
			cmd.Env = append(os.Environ(), "XTABLES_LIBDIR="+l.profile.extension)
			data, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != row.code || string(data) != row.output || (err == nil) != (row.code == 0) {
				t.Fatal("private alias ABI", row.alias, err, string(data))
			}
			if _, err := os.Lstat(filepath.Join(root, "started")); !os.IsNotExist(err) {
				t.Fatal("metadata/unknown argv started diagnostic")
			}
		})
	}
	// Actual original held image executes the same wait-for-release protocol;
	// cancellation must kill/join it without emitting a diagnostic or release.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-N", "-6", "-j", "route", "show", "table", "205")
	cmd.Args[0] = wgInactivityChildAlias
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = append(os.Environ(), "XTABLES_LIBDIR="+l.profile.extension)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		cancel()
		if !waited {
			waited = true
			_ = cmd.Wait()
		}
	}()
	for {
		if _, err := os.Stat(filepath.Join(root, "started")); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("small helper did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	waited = true
	err := cmd.Wait()
	if err == nil || output.Len() != 0 {
		t.Fatal("canceled helper supplied diagnostic", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "release")); !os.IsNotExist(err) {
		t.Fatal("cancel synthesized release")
	}
}
