package components

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type initialInstallModelSource struct {
	calls  int
	failAt int
}

func (s *initialInstallModelSource) WithInitialNFQWSInstall(c context.Context, effect func(context.Context, func(context.Context) error) error) error {
	return effect(c, func(context.Context) error {
		s.calls++
		if s.failAt == s.calls {
			return errors.New("model actual-source refusal")
		}
		return nil
	})
}

type initialInstallModelRunner struct {
	t         *testing.T
	m         *Manager
	before    []byte
	installed bool
	commands  int
	fail      string
	onStatus  func()
}

func (r *initialInstallModelRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if len(args) != 1 || args[0] != "status" {
		r.t.Fatal("unexpected plain package runner", args)
	}
	if r.onStatus != nil {
		r.onStatus()
	}
	if !r.installed {
		return bytes.Clone(r.before), nil
	}
	return append(bytes.Clone(r.before), []byte("\nPackage: nfqws2-keenetic\nVersion: 1.3.1\nStatus: install user installed\n")...), nil
}

// Models the joined package-command contract only; no native process/queue
// ownership is claimed. The separate Linux hook test executes actual scripts.
func (r *initialInstallModelRunner) runSupervised(ctx context.Context, _ string, args []string, record packageSupervision, root *ownedfs.Root, path string) ([]byte, error) {
	r.commands++
	if record.Action != "install" || len(args) != 3 || args[0] != "install" || args[1] != "--nodeps" {
		r.t.Fatal("unsafe install argv", record, args)
	}
	pending, isPending, err := r.m.PendingManagedUpdate()
	if err != nil || !isPending || pending.SchemaVersion != 4 || pending.Phase != nfqwsInitialStarted {
		r.t.Fatal("package started without durable initial intent", pending, isPending, err)
	}
	if r.fail == "before-unpack" {
		return nil, errors.New("model command ambiguous")
	}
	data, err := os.ReadFile(args[2])
	if err != nil {
		return nil, err
	}
	_, outer, err := nfqwsInitialTar(ctx, data)
	if err != nil {
		return nil, err
	}
	var payload, controls []nfqwsInitialMember
	for _, member := range outer {
		switch member.name {
		case "data.tar.gz":
			_, payload, err = nfqwsInitialTar(ctx, member.data)
		case "control.tar.gz":
			_, controls, err = nfqwsInitialTar(ctx, member.data)
		}
		if err != nil {
			return nil, err
		}
	}
	prefix, _ := r.m.nfqwsInitialPrefix()
	var files []string
	for _, member := range payload {
		if member.header.Typeflag == '5' || member.name == "" {
			continue
		}
		if member.header.Uid != 0 || member.header.Gid != 0 {
			r.t.Fatal("derivative retained build owner", member.name)
		}
		rel := strings.TrimPrefix(member.name, "opt/")
		target := filepath.Join(prefix, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(target, member.data, os.FileMode(member.header.Mode)); err != nil {
			return nil, err
		}
		files = append(files, "/"+member.name)
		if r.fail == "partial-unpack" && member.name == nfqwsInitialInitMember {
			return nil, errors.New("model interrupted after inert init")
		}
	}
	for _, member := range controls {
		if member.name == "" || member.header.Typeflag == '5' {
			continue
		}
		if err := os.WriteFile(filepath.Join(r.m.infoDir(), "nfqws2-keenetic."+member.name), member.data, 0644); err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	if err := os.WriteFile(filepath.Join(r.m.infoDir(), "nfqws2-keenetic.list"), []byte(strings.Join(files, "\n")+"\n"), 0644); err != nil {
		return nil, err
	}
	selected := "nfqws2-" + nfqwsInitialArchitectures[r.m.Arch]
	binary, err := os.ReadFile(filepath.Join(prefix, "tmp", "nfqws2_binary", selected))
	if err != nil {
		return nil, err
	}
	if r.fail == "bad-relocated-binary" {
		binary = []byte("postinst cp did not produce reviewed executable")
	}
	if err := os.WriteFile(filepath.Join(prefix, "usr", "bin", "nfqws2"), binary, 0755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(prefix, "tmp", "nfqws2_binary"))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(prefix, "tmp", "nfqws2_binary", entry.Name())); err != nil {
			return nil, err
		}
	}
	if err := os.Remove(filepath.Join(prefix, "tmp", "nfqws2_binary")); err != nil {
		return nil, err
	}
	r.installed = true
	if r.fail == "after-command" {
		return nil, errors.New("model lost package completion")
	}
	return []byte("joined model opkg"), nil
}

func initialInstallFixture(t *testing.T) (*Manager, *initialInstallModelRunner, NFQWSInitialInstallAuthority) {
	t.Helper()
	path := os.Getenv("RAZVILKA_NFQWS_INITIAL_IPK")
	if path == "" {
		path = filepath.Join("..", "..", ".review-local", "nfq-initial-install-review", "upstream-1.3.1-all-entware.ipk")
	}
	source, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("private pinned upstream evidence not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	prefix := filepath.Join(base, "opt")
	m := &Manager{StateDir: filepath.Join(base, "state"), InitDir: filepath.Join(prefix, "etc", "init.d"), BinDir: filepath.Join(prefix, "bin"), InfoDir: filepath.Join(prefix, "lib", "opkg", "info"), Opkg: "simulated-opkg", Arch: "arm64"}
	for _, path := range []string{prefix, m.InitDir, m.InfoDir, filepath.Join(prefix, "usr", "bin")} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	m.nfqwsFixture = &managedNFQWSFixtureBoundary{base, info}
	r := &initialInstallModelRunner{t: t, m: m, before: []byte("Package: iptables\nVersion: 1\nStatus: install user installed\n\nPackage: busybox\nVersion: 2\nStatus: install ok installed\n")}
	m.Runner = r
	m.initialNFQSource = &initialInstallModelSource{}
	m.Client = &http.Client{Transport: bundleFixtureTransport(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != nfqwsInitialSourceURL {
			t.Fatal("unreviewed download", request.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(source)), Header: make(http.Header)}, nil
	})}
	a := NFQWSInitialInstallAuthority{InstallationID: strings.Repeat("a", 32), Sequence: 1, Check: func(_ context.Context, _ string, _, _ uint64, reader int) error {
		if reader != 4 {
			t.Fatal("wrong admission schema", reader)
		}
		return nil
	}}
	return m, r, a
}

func TestNFQWSInitialInstallJoinedReadbackAndAmbiguousFence(t *testing.T) {
	for _, failure := range []string{"", "before-unpack", "partial-unpack", "bad-relocated-binary", "after-command"} {
		t.Run(failure, func(t *testing.T) {
			m, r, a := initialInstallFixture(t)
			r.fail = failure
			result, err := m.InstallInitialNFQWS(context.Background(), a)
			state, pending, readErr := m.PendingManagedUpdate()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if failure == "" {
				if err != nil || !result.OK || !result.InstalledIdleAccepted || pending || state.Phase != nfqwsInitialAccepted {
					t.Fatal("joined readback not accepted", result, state, pending, err)
				}
				if floor, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); err != nil || floor != 4 {
					t.Fatal("accepted provenance lost reader floor", floor, err)
				}
			} else {
				if err == nil || result.OK || result.InstalledIdleAccepted || !pending || state.Phase != nfqwsInitialStarted {
					t.Fatal("ambiguous install lost fence", result, state, pending, err)
				}
				before := r.commands
				if _, err := m.InstallInitialNFQWS(context.Background(), a); err == nil || r.commands != before {
					t.Fatal("ambiguous install replayed")
				}
				for _, action := range []string{"rollback", "accept-live", "accept-installed-idle", "abandon-prepared"} {
					_, err := m.RecoverManagedUpdate(context.Background(), ManagedRecoveryRequest{TransactionID: state.TransactionID, Component: "nfqws2", Action: action}, func(context.Context) error { return nil }, func(context.Context) error { return nil })
					if !errors.Is(err, ErrNFQWSInitialInstall) {
						t.Fatal("generic recovery settled initial install", action, err)
					}
				}
			}
			if r.commands != 1 {
				t.Fatal("unexpected opkg command count", r.commands)
			}
		})
	}
}

func TestNFQWSInitialInstallRefusesPristineAndAuthorityChanges(t *testing.T) {
	for _, change := range []string{"no-source", "no-authority", "existing-main", "pending-other-package", "before-command-policy", "after-command-authority", "foreign-current"} {
		t.Run(change, func(t *testing.T) {
			m, r, a := initialInstallFixture(t)
			switch change {
			case "no-source":
				m.initialNFQSource = nil
			case "no-authority":
				a.Check = nil
			case "existing-main":
				if err := os.MkdirAll(filepath.Join(filepath.Dir(m.InitDir), "nfqws2"), 0755); err != nil {
					t.Fatal(err)
				}
			case "pending-other-package":
				r.before = append(r.before, []byte("\nPackage: unrelated\nVersion: 1\nStatus: install ok unpacked\n")...)
			case "before-command-policy":
				m.updateFault = func(point string) error {
					if point == "before:initial-install-command" {
						return errors.New("policy changed")
					}
					return nil
				}
			case "after-command-authority":
				m.updateFault = func(point string) error {
					if point == "after:initial-install-command" {
						a.Check = func(context.Context, string, uint64, uint64, int) error { return ErrRecoveryAuthority }
						return ErrRecoveryAuthority
					}
					return nil
				}
			case "foreign-current":
				m.updateFault = func(point string) error {
					if point == "before:"+nfqwsInitialStarted {
						return os.WriteFile(filepath.Join(m.updateJournalDir(), "current.json"), []byte("foreign image\n"), 0600)
					}
					return nil
				}
			}
			result, err := m.InstallInitialNFQWS(context.Background(), a)
			if err == nil || result.OK {
				t.Fatal("unsafe initial install accepted", result, err)
			}
			if change != "after-command-authority" && r.commands != 0 {
				t.Fatal("rejected input reached opkg", r.commands)
			}
			if change == "foreign-current" {
				data, err := os.ReadFile(filepath.Join(m.updateJournalDir(), "current.json"))
				if err != nil || string(data) != "foreign image\n" {
					t.Fatal("third journal image overwritten", string(data), err)
				}
			}
		})
	}
}

func TestNFQWSInitialInstallClosingReadbackRefusesChangedAssets(t *testing.T) {
	for _, point := range []string{"after:initial-install-readback", "before:" + nfqwsInitialAccepted} {
		for _, asset := range []string{"init", "binary", "lua", "metadata-mode", "metadata-owner"} {
			t.Run(point+"/"+asset, func(t *testing.T) {
				if (asset == "metadata-mode" || asset == "metadata-owner") && runtime.GOOS != "linux" {
					t.Skip("POSIX metadata is exercised on Linux")
				}
				if asset == "metadata-owner" && os.Geteuid() != 0 {
					t.Skip("root-only metadata adversary fixture")
				}
				m, r, a := initialInstallFixture(t)
				m.updateFault = func(at string) error {
					if at != point {
						return nil
					}
					prefix, _ := m.nfqwsInitialPrefix()
					switch asset {
					case "init":
						stock, err := os.ReadFile(filepath.Join("testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
						if err != nil {
							return err
						}
						return os.WriteFile(filepath.Join(m.InitDir, "S51nfqws2"), stock, 0755)
					case "binary":
						return os.WriteFile(filepath.Join(prefix, "usr", "bin", "nfqws2"), []byte("foreign binary"), 0755)
					case "lua":
						return os.WriteFile(filepath.Join(prefix, "etc", "nfqws2", "lua", "zapret-lib.lua.gz"), []byte("foreign Lua"), 0644)
					case "metadata-mode":
						return os.Chmod(filepath.Join(m.infoDir(), "nfqws2-keenetic.control"), 0664)
					case "metadata-owner":
						// Enforce the production UID/GID contract for this adversary;
						// the private model fixture otherwise permits the test UID.
						m.nfqwsFixture = nil
						return os.Chown(filepath.Join(m.infoDir(), "nfqws2-keenetic.list"), 1001, 1001)
					}
					return nil
				}
				result, err := m.InstallInitialNFQWS(context.Background(), a)
				if err == nil || result.OK || r.commands != 1 {
					t.Fatal("changed closing assets accepted", result, err, r.commands)
				}
				state, pending, err := m.PendingManagedUpdate()
				if err != nil || !pending || state.Phase != nfqwsInitialStarted {
					t.Fatal("changed image lost initial fence", state, pending, err)
				}
			})
		}
	}
}

func TestNFQWSInitialInstallNewForeignConfigBeforeCommandIsPreserved(t *testing.T) {
	m, r, a := initialInstallFixture(t)
	foreign := filepath.Join(filepath.Dir(m.InitDir), "nfqws2", "nfqws2.conf")
	m.updateFault = func(point string) error {
		if point != "before:initial-install-command" {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(foreign), 0755); err != nil {
			return err
		}
		return os.WriteFile(foreign, []byte("FOREIGN=keep\n"), 0600)
	}
	if _, err := m.InstallInitialNFQWS(context.Background(), a); err == nil {
		t.Fatal("new foreign config accepted")
	}
	data, err := os.ReadFile(foreign)
	if err != nil || string(data) != "FOREIGN=keep\n" || r.commands != 0 {
		t.Fatal("foreign config was migrated/overwritten", string(data), err, r.commands)
	}
	if _, pending, err := m.PendingManagedUpdate(); err != nil || !pending {
		t.Fatal("intent fence disappeared", pending, err)
	}
}

func TestNFQWSInitialInstallClosingReadbackCannotOutliveAuthority(t *testing.T) {
	m, r, a := initialInstallFixture(t)
	revoked := false
	original := a.Check
	a.Check = func(c context.Context, id string, sequence, revision uint64, reader int) error {
		if revoked {
			return ErrRecoveryAuthority
		}
		return original(c, id, sequence, revision, reader)
	}
	m.updateFault = func(point string) error {
		if point == "before:"+nfqwsInitialAccepted {
			r.onStatus = func() { revoked = true }
		}
		return nil
	}
	result, err := m.InstallInitialNFQWS(context.Background(), a)
	if err == nil || result.OK || !revoked || r.commands != 1 {
		t.Fatal("closing readback outlived authority", result, err, revoked, r.commands)
	}
	state, pending, err := m.PendingManagedUpdate()
	if err != nil || !pending || state.Phase != nfqwsInitialStarted {
		t.Fatal("authority revocation lost pending fence", state, pending, err)
	}
}
