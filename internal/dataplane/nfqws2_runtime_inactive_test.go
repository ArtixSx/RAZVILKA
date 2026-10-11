package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type nfqws2InactiveFixture struct {
	a       *NFQWS2Adapter
	source  *NFQWSRuntimeInactiveSource
	proof   nfqws2InactivePlatform
	image   BackendInventorySnapshot
	uses    int
	reads   int
	closing func()
}

// Private complete-source models only. Production never accepts these callback
// or DTO inputs and always opens the actual provider/collector/proc inventory.
func newNFQWS2InactiveFixture(t *testing.T) *nfqws2InactiveFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runtime", "global", "proc"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	a := NewNFQWS2Adapter()
	a.StateRoot = filepath.Join(root, "runtime", "nfqws2")
	a.ConfigPath, a.InitPath = filepath.Join(root, "global", "nfqws2.conf"), filepath.Join(root, "global", "S51nfqws2")
	a.UserListPath, a.IPSetListPath = filepath.Join(root, "global", "user.list"), filepath.Join(root, "global", "ipset.list")
	for _, path := range []string{a.ConfigPath, a.InitPath, a.UserListPath, a.IPSetListPath} {
		if err := os.WriteFile(path, []byte("# fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	identity, _ := networkPolicyIdentityFixture()
	provider := netidentity.NewProcProvider()
	image := networkPolicyInventoryTestImage(identity.value, nil)
	inventory := &BackendInventory{review: image.Scope.ToolReviewID, reader: backendInventoryReader{
		Provider: provider, Runner: a.Runner, IPTables: image.IPTables, IP6Tables: image.IP6Tables,
		NFTABI: backendNFTABILinux70, CheckTools: func(context.Context, backendInventoryScope) error { return nil },
	}}
	f := &nfqws2InactiveFixture{a: a, image: image}
	f.proof = nfqws2InactivePlatform{
		procRoot: filepath.Join(root, "proc"), selfPID: 1,
		readlink: func(string) (string, error) { return filepath.Join(root, "controller"), nil },
		protected: func(info os.FileInfo, directory, private bool) bool {
			if info == nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || !directory && !info.Mode().IsRegular() {
				return false
			}
			// Windows models have no POSIX UID/mode proof. Production Windows
			// refuses in the platform factory before reading any source.
			return runtime.GOOS == "windows" || info.Mode().Perm()&0022 == 0 && (!private || info.Mode().Perm()&0077 == 0)
		},
		queues: func(context.Context) ([]nfqwsScopedQueue, error) { return nil, nil },
		sockets: func(context.Context) (string, error) {
			return "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n", nil
		},
	}
	r := &NFQWSRuntimeInactiveSource{adapter: a, startup: *a, inventory: inventory, frozen: *inventory, provider: provider, identity: identity.value, platform: f.proof}
	r.self = r
	f.source = r
	if err := r.Bind(a); err != nil {
		t.Fatal(err)
	}
	f.process(t, 1, "controller", 'S', 0, "controller\x00")
	return f
}

func (f *nfqws2InactiveFixture) process(t *testing.T, pid int, name string, state byte, flags uint64, command string) {
	t.Helper()
	path := filepath.Join(f.proof.procRoot, fmt.Sprint(pid))
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[6], fields[19] = string(state), fmt.Sprint(flags), "123"
	if err := os.WriteFile(filepath.Join(path, "stat"), []byte(fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cmdline"), []byte(command), 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *nfqws2InactiveFixture) verify(ctx context.Context) error {
	return f.source.verifyWithSources(ctx, f.proof,
		func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
			f.uses++
			err := use(c, f.source.identity)
			if f.closing != nil {
				f.closing()
			}
			return err
		},
		func(c context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
			f.reads++
			return nfqwsDirectStockTestClone(f.image), c.Err()
		})
}

func nfqws2InactiveTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestNFQWSIndependentInactiveColdRequiresEveryFreshSource(t *testing.T) {
	f := newNFQWS2InactiveFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	before, err := nfqws2ReadInactiveFiles(ctx, f.a, f.proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verify(ctx); err != nil || f.uses != 1 || f.reads != 2 {
		t.Fatal("cold empty lease was substituted for actual observations", err)
	}
	after, err := nfqws2ReadInactiveFiles(ctx, f.a, f.proof)
	if err != nil || !before.same(after) {
		t.Fatal("observer wrote or created runtime state", err)
	}
	if _, err := os.Stat(f.a.StateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("observer created a never-used runtime directory")
	}
	// Public API cannot acquire this private modeled source on Windows or
	// manufacture a native grant from Background / copied adapter/source.
	if _, err := NewNFQWSRuntimeInactiveSource(context.Background(), f.a, f.source.inventory); err == nil {
		t.Fatal("unbounded constructor acquired source")
	}
	if err := f.verify(context.Background()); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
		t.Fatal("unbounded observation acquired grant")
	}
}

func TestNFQWSIndependentInactiveEachCallRereadsProcessesKernelAndFiles(t *testing.T) {
	f := newNFQWS2InactiveFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	if err := f.verify(ctx); err != nil {
		t.Fatal(err)
	}
	f.process(t, 2, "nfqws2", 'S', 0, "nfqws2\x00--qnum=1104\x00")
	if err := f.verify(ctx); !errors.Is(err, ErrNFQWSManagedProcessUnknown) || NFQWSRuntimeInactiveStage(err) != "processes" {
		t.Fatal("earlier absence was cached", err)
	}
	if f.uses != 2 || f.reads != 2 {
		t.Fatal("process refusal reached a kernel grant")
	}
}

func TestNFQWSIndependentInactiveProcUnknownAndOwnedIncarnationsHold(t *testing.T) {
	for _, kind := range []string{"empty-root", "empty-command", "nfq-zombie", "renamed-argv", "supervisor", "config", "qnum", "birth-change"} {
		t.Run(kind, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			switch kind {
			case "empty-root":
				f.proof.procRoot = t.TempDir()
			case "empty-command":
				f.process(t, 2, "other", 'S', 0, "")
			case "nfq-zombie":
				f.process(t, 2, "nfqws", 'Z', 0, "")
			case "renamed-argv":
				f.process(t, 2, "other", 'S', 0, "nfqws\x00")
			case "supervisor":
				f.process(t, 2, "controller", 'S', 0, "controller\x00nfqws-managed-process-supervisor\x00")
			case "config":
				f.process(t, 2, "shell", 'S', 0, "shell\x00--config="+f.a.ConfigPath+"\x00")
			case "qnum":
				f.process(t, 2, "other", 'S', 0, "renamed\x00--qnum=1104\x00")
			case "birth-change":
				f.proof.readlink = func(string) (string, error) {
					stat := filepath.Join(f.proof.procRoot, "1", "stat")
					data, err := os.ReadFile(stat)
					if err != nil {
						return "", err
					}
					if err := os.WriteFile(stat, []byte(strings.Replace(string(data), "123", "124", 1)), 0600); err != nil {
						return "", err
					}
					return "controller", nil
				}
			}
			if err := nfqws2InactiveProcesses(ctx, f.proof, f.a); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
				t.Fatal("missing/owned/unknown process inventory passed", err)
			}
		})
	}
}

func TestNFQWSIndependentInactivePendingPrivateStateAndManagedListsHold(t *testing.T) {
	for _, kind := range []string{"unknown-lease", "pending-file", "bad-lock", "managed-list", "writable-root"} {
		t.Run(kind, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			if err := os.Mkdir(f.a.StateRoot, 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown-lease":
				if err := os.WriteFile(filepath.Join(f.a.StateRoot, nfqws2LeaseFile), []byte(`{"unknown":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-file":
				if err := os.WriteFile(filepath.Join(f.a.StateRoot, ".pending"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-lock":
				if err := os.WriteFile(filepath.Join(f.a.StateRoot, ".state-"+nfqws2Hash([]byte(nfqws2LeaseFile))+".lock"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "managed-list":
				if err := os.WriteFile(f.a.UserListPath, []byte(managedBegin+"\nprivate.example\n"+managedEnd+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "writable-root":
				if err := os.Chmod(f.a.StateRoot, 0777); err != nil {
					t.Fatal(err)
				}
				original := f.proof.protected
				f.proof.protected = func(info os.FileInfo, directory, private bool) bool {
					return (info == nil || info.Name() != "nfqws2") && original(info, directory, private)
				}
			}
			if err := f.verify(ctx); !errors.Is(err, ErrNFQWSManagedKernelOwner) || f.reads != 0 {
				t.Fatal("pending state became absence or reached kernel grant", err)
			}
		})
	}
}

func TestNFQWSIndependentInactiveDetectsDriftAfterProviderClosing(t *testing.T) {
	for _, kind := range []string{"file", "participant", "reader", "tool-source"} {
		t.Run(kind, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			f.closing = func() {
				switch kind {
				case "file":
					if err := os.WriteFile(f.a.ConfigPath, []byte("changed\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "participant":
					f.a.activeProcess = &nfqws2ActiveOwner{}
				case "reader":
					f.source.inventory.reader.IP6Tables += "-replaced"
				case "tool-source":
					f.source.inventory.review = strings.Repeat("b", 64)
				}
			}
			if err := f.verify(ctx); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
				t.Fatal("post-provider drift acquired inactivity", err)
			}
		})
	}
}

func TestNFQWSIndependentInactiveSourceCannotBeCopiedReboundOrSubstituted(t *testing.T) {
	f := newNFQWS2InactiveFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	if err := f.source.Bind(f.a); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
		t.Fatal("source rebound")
	}
	copiedAdapter := *f.a
	if err := copiedAdapter.VerifyRuntimeInactive(ctx); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
		t.Fatal("copied adapter acquired source")
	}
	copiedSource := *f.source
	if err := copiedSource.Bind(f.a); !errors.Is(err, ErrNFQWSManagedKernelOwner) {
		t.Fatal("copied source acquired association")
	}
	f.image.Scope.ToolReviewID = strings.Repeat("b", 64)
	if err := f.verify(ctx); !errors.Is(err, ErrNFQWSManagedKernelOwner) || NFQWSRuntimeInactiveStage(err) != "inventory.source" {
		t.Fatal("another collector snapshot supplied proof", err)
	}
}

func TestNFQWSIndependentInactivePublicErrorsAreFixedAndUnwrap(t *testing.T) {
	private := errors.New("private-addr-file-command")
	err := nfqws2InactiveAt("observation", nfqws2InactiveAt("processes", private))
	if strings.Contains(err.Error(), private.Error()) || !errors.Is(err, private) || !errors.Is(err, ErrNFQWSManagedKernelOwner) || NFQWSRuntimeInactiveStage(err) != "processes" {
		t.Fatal("private error leaked or original cause discarded")
	}
}
