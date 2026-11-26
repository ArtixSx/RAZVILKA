package selfupdatejournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const transaction = "0123456789abcdef0123456789abcdef"

var okay Check = func(context.Context) error { return nil }
var interrupted = errors.New("fault interruption")

type fixture struct {
	installation, journal, candidate string
	store                            *Store
	files                            []File
}

func fixtureAt(t *testing.T, work string) *fixture {
	t.Helper()
	f := &fixture{installation: filepath.Join(work, "installation"), journal: filepath.Join(work, "journal"), candidate: filepath.Join(work, "candidate")}
	for _, dir := range []string{f.journal, f.candidate, filepath.Join(f.installation, "bin"), filepath.Join(f.installation, "etc/razvilka")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		path, text string
		mode       os.FileMode
	}{{filepath.Join(f.installation, "bin/razvilka"), "old binary", 0755}, {filepath.Join(f.candidate, "binary"), "new binary", 0600}, {filepath.Join(f.candidate, "config"), "new config", 0600}} {
		if err := os.WriteFile(item.path, []byte(item.text), item.mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ target, source, content string }{{"bin/razvilka", "binary", "new binary"}, {"etc/razvilka/config.json", "config", "new config"}} {
		hash := sha256.Sum256([]byte(item.content))
		f.files = append(f.files, File{Target: item.target, Candidate: filepath.Join(f.candidate, item.source), SHA256: hex.EncodeToString(hash[:])})
	}
	f.reopen(t)
	t.Cleanup(func() { f.store.Close() })
	return f
}

func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	if f.store != nil {
		f.store.Close()
	}
	var err error
	f.store, err = Open(f.installation, f.journal)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) prepare(t *testing.T) {
	t.Helper()
	if err := f.store.Prepare(context.Background(), transaction, f.files, okay, okay); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) install(t *testing.T) {
	t.Helper()
	if err := f.store.Install(context.Background(), transaction, okay, okay); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) old(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.installation, "bin/razvilka"))
	if err != nil || string(data) != "old binary" {
		t.Fatalf("LKG not restored: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(f.installation, "etc/razvilka/config.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original absence lost: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(f.journal, transaction, "old-0"))
	if err != nil || string(data) != "old binary" {
		t.Fatalf("LKG image not retained: %q %v", data, err)
	}
}

func seed(t *testing.T, f *fixture, operation string) {
	t.Helper()
	if operation == "prepare" {
		return
	}
	f.prepare(t)
	if operation == "install" {
		return
	}
	f.install(t)
	if operation == "accept-rollback" {
		if err := f.store.Restore(context.Background(), transaction, okay, okay); err != nil {
			t.Fatal(err)
		}
	}
}

func perform(f *fixture, operation string, run Check) error {
	ctx := context.Background()
	switch operation {
	case "prepare":
		return f.store.Prepare(ctx, transaction, f.files, okay, okay)
	case "install":
		return f.store.Install(ctx, transaction, okay, okay)
	case "restore":
		return f.store.Restore(ctx, transaction, okay, okay)
	case "execute":
		return f.store.Execute(ctx, transaction, "start-candidate", okay, run)
	case "accept":
		return f.store.Accept(ctx, transaction, false, okay, okay)
	case "accept-rollback":
		return f.store.Accept(ctx, transaction, true, okay, okay)
	}
	return errors.New("bad operation")
}

func TestFileJournalFaultMatrix(t *testing.T) {
	for _, operation := range []string{"prepare", "install", "restore", "execute", "accept", "accept-rollback"} {
		t.Run(operation, func(t *testing.T) {
			baseline := fixtureAt(t, t.TempDir())
			seed(t, baseline, operation)
			var points []string
			baseline.store.fault = func(point string) error { points = append(points, point); return nil }
			if err := perform(baseline, operation, okay); err != nil {
				t.Fatal(err)
			}
			for index, point := range points {
				t.Run(fmt.Sprintf("%02d-%s", index, point), func(t *testing.T) {
					f := fixtureAt(t, t.TempDir())
					seed(t, f, operation)
					at, ran := 0, 0
					f.store.fault = func(string) error {
						at++
						if at == index+1 {
							return interrupted
						}
						return nil
					}
					if err := perform(f, operation, func(context.Context) error { ran++; return nil }); !errors.Is(err, interrupted) {
						t.Fatalf("fault did not stop operation: %v", err)
					}
					f.reopen(t)
					r, present, err := f.store.Current()
					if err != nil {
						t.Fatal(err)
					}
					if !present {
						data, _ := os.ReadFile(filepath.Join(f.installation, "bin/razvilka"))
						if string(data) != "old binary" {
							t.Fatal("unpublished prepare changed files")
						}
						return
					}
					if r.Pending() && f.store.Prepare(context.Background(), strings.Repeat("a", 32), f.files, okay, okay) == nil {
						t.Fatal("pending transaction overwritten")
					}
					if r.Phase == "command-started" {
						if !errors.Is(f.store.Execute(context.Background(), transaction, "start-candidate", okay, func(context.Context) error { ran++; return nil }), ErrUnknown) {
							t.Fatal("unknown replay was allowed")
						}
						if !errors.Is(f.store.Restore(context.Background(), transaction, okay, okay), ErrUnknown) {
							t.Fatal("unknown was implicitly repaired")
						}
						if err := f.store.ResolveUnknown(context.Background(), transaction, okay, okay, okay); err != nil {
							t.Fatal(err)
						}
					}
					if ran > 1 {
						t.Fatal("external effect repeated")
					}
					if r.Phase == "accepted" {
						if _, err := os.Stat(filepath.Join(f.journal, transaction, "old-0")); err != nil {
							t.Fatal(err)
						}
						return
					}
					if r.Phase != "rolled-back" {
						if err := f.store.Restore(context.Background(), transaction, okay, okay); err != nil {
							t.Fatal(err)
						}
						if err := f.store.Accept(context.Background(), transaction, true, okay, okay); err != nil {
							t.Fatal(err)
						}
					}
					f.old(t)
				})
			}
			t.Logf("%d fault boundaries", len(points))
		})
	}
}

func TestFileJournalResumeAfterAtomicRename(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	f.store.fault = func(point string) error {
		if point == "after:rename:file:0" {
			return interrupted
		}
		return nil
	}
	if err := f.store.Install(context.Background(), transaction, okay, okay); !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
	f.reopen(t)
	f.install(t)
	r, _, err := f.store.Current()
	if err != nil || r.Phase != "installed" {
		t.Fatalf("resume: %+v %v", r, err)
	}
	if err := f.store.Accept(context.Background(), transaction, false, okay, okay); err != nil {
		t.Fatal(err)
	}
	// A later transaction retains the first receipt and its LKG.
	if err := f.store.Prepare(context.Background(), strings.Repeat("b", 32), f.files, okay, okay); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old-0", "new-0", "receipt.json"} {
		if _, err := os.Stat(filepath.Join(f.journal, transaction, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileJournalUnknownAndMonotonicCommands(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	f.install(t)
	ran := 0
	effect := func(context.Context) error { ran++; return nil }
	for _, command := range []string{"migrate", "start"} {
		if err := f.store.Execute(context.Background(), transaction, command, okay, effect); err != nil {
			t.Fatal(err)
		}
	}
	f.reopen(t)
	if err := f.store.Execute(context.Background(), transaction, "migrate", okay, effect); !errors.Is(err, ErrPending) || ran != 2 {
		t.Fatalf("older effect replay: %v count=%d", err, ran)
	}
	if err := f.store.Execute(context.Background(), transaction, "ambiguous", okay, func(context.Context) error { ran++; return interrupted }); !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
	f.reopen(t)
	for _, err := range []error{f.store.Install(context.Background(), transaction, okay, okay), f.store.Restore(context.Background(), transaction, okay, okay), f.store.Accept(context.Background(), transaction, false, okay, okay)} {
		if !errors.Is(err, ErrUnknown) {
			t.Fatalf("unknown fence: %v", err)
		}
	}
	if err := f.store.ResolveUnknown(context.Background(), transaction, okay, nil, okay); err == nil {
		t.Fatal("no independent quiescence")
	}
	if err := f.store.ResolveUnknown(context.Background(), transaction, okay, okay, nil); !errors.Is(err, ErrUnknown) {
		t.Fatal("no independent outcome")
	}
	if err := f.store.ResolveUnknown(context.Background(), transaction, okay, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Restore(context.Background(), transaction, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Execute(context.Background(), transaction, "restart-lkg", okay, effect); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Accept(context.Background(), transaction, false, okay, okay); err == nil {
		t.Fatal("rollback accepted as candidate")
	}
	if err := f.store.Accept(context.Background(), transaction, true, okay, okay); err != nil {
		t.Fatal(err)
	}
	f.old(t)
}

func TestFileJournalFencesCorruptionAndForeignEdits(t *testing.T) {
	for _, damage := range []string{"pointer-schema", "receipt-schema", "receipt-phase", "receipt-index", "snapshot", "target", "mode"} {
		t.Run(damage, func(t *testing.T) {
			f := fixtureAt(t, t.TempDir())
			f.prepare(t)
			switch damage {
			case "pointer-schema":
				if err := os.WriteFile(filepath.Join(f.journal, "current.json"), []byte(`{"schema":99,"id":"`+transaction+`"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "snapshot":
				if err := os.WriteFile(filepath.Join(f.journal, transaction, "old-0"), []byte("foreign snapshot"), 0600); err != nil {
					t.Fatal(err)
				}
			case "target":
				if err := os.WriteFile(filepath.Join(f.installation, "bin/razvilka"), []byte("foreign target"), 0755); err != nil {
					t.Fatal(err)
				}
			case "mode":
				f.install(t)
				if err := os.Chmod(filepath.Join(f.installation, "bin/razvilka"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := f.store.Accept(context.Background(), transaction, false, okay, okay); err == nil && os.PathSeparator != '\\' {
					t.Fatal("wrong binary mode accepted")
				}
				return
			default:
				r, _, _ := f.store.Current()
				switch damage {
				case "receipt-schema":
					r.Schema = 99
				case "receipt-phase":
					r.Phase = "success-maybe"
				case "receipt-index":
					r.Index = 99
				}
				data, _ := json.Marshal(r)
				if err := os.WriteFile(filepath.Join(f.journal, transaction, "receipt.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.reopen(t)
			if err := f.store.Install(context.Background(), transaction, okay, okay); err == nil {
				t.Fatal("damaged journal installed")
			}
			if err := f.store.Prepare(context.Background(), strings.Repeat("c", 32), f.files, okay, okay); err == nil {
				t.Fatal("damage erased by new transaction")
			}
		})
	}
}

func TestFileJournalAuthorityQuiescenceMatchingAndSymlinks(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	ctx := context.Background()
	if err := f.store.Prepare(ctx, transaction, f.files, nil, okay); err == nil {
		t.Fatal("missing authority")
	}
	if err := f.store.Prepare(ctx, transaction, f.files, okay, nil); err == nil {
		t.Fatal("missing quiescence")
	}
	f.prepare(t)
	if err := f.store.Install(ctx, strings.Repeat("d", 32), okay, okay); !errors.Is(err, ErrMismatch) {
		t.Fatal("wrong transaction accepted")
	}
	stopped := false
	authority := func(context.Context) error {
		if stopped {
			return interrupted
		}
		return nil
	}
	f.store.fault = func(point string) error {
		if point == "before:rename:file:0" {
			stopped = true
		}
		return nil
	}
	if err := f.store.Install(ctx, transaction, authority, okay); !errors.Is(err, interrupted) {
		t.Fatal("Stop change after intent ignored")
	}
	data, _ := os.ReadFile(filepath.Join(f.installation, "bin/razvilka"))
	if string(data) != "old binary" {
		t.Fatal("Stop changed file")
	}
	f.reopen(t)
	f.install(t)
	if err := f.store.Accept(ctx, transaction, false, okay, func(context.Context) error { return interrupted }); !errors.Is(err, interrupted) {
		t.Fatal("failed live evidence accepted")
	}
	r, _, _ := f.store.Current()
	if !r.Pending() {
		t.Fatal("candidate probe released receipt")
	}
	t.Run("symlink", func(t *testing.T) {
		if err := os.Remove(filepath.Join(f.installation, "bin/razvilka")); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(f.candidate, "outside")
		if err := os.WriteFile(outside, []byte("foreign"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(f.installation, "bin/razvilka")); err != nil {
			t.Skipf("symlink permission unavailable: %v", err)
		}
		if err := f.store.Restore(ctx, transaction, okay, okay); err == nil {
			t.Fatal("symlink restored")
		}
		data, _ = os.ReadFile(outside)
		if string(data) != "foreign" {
			t.Fatal("foreign symlink destination changed")
		}
	})
}

func TestFileJournalPreparationRejectsUnverifiedAndOutsideFiles(t *testing.T) {
	for _, issue := range []string{"checksum", "outside", "duplicate"} {
		t.Run(issue, func(t *testing.T) {
			f := fixtureAt(t, t.TempDir())
			switch issue {
			case "checksum":
				f.files[0].SHA256 = strings.Repeat("0", 64)
			case "outside":
				f.files[0].Target = "etc/foreign.conf"
			case "duplicate":
				f.files = append(f.files, f.files[0])
			}
			if err := f.store.Prepare(context.Background(), transaction, f.files, okay, okay); !errors.Is(err, ErrMismatch) {
				t.Fatalf("invalid preparation authorized: %v", err)
			}
			if _, present, err := f.store.Current(); err != nil || present {
				t.Fatal("invalid preparation published a transaction")
			}
			data, _ := os.ReadFile(filepath.Join(f.installation, "bin/razvilka"))
			if string(data) != "old binary" {
				t.Fatal("invalid preparation changed LKG")
			}
		})
	}
}

func TestFileJournalWriterLock(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	unlock, err := lockWriter(f.store.journal)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(f.installation, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := fresh.Install(context.Background(), transaction, okay, okay); err == nil {
		t.Fatal("second writer acquired busy journal")
	}
	unlock()
	if err := fresh.Install(context.Background(), transaction, okay, okay); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.journal, ".writer.lock")); err != nil {
		t.Fatal("lock inode removed")
	}
}

func TestFileJournalSubprocessCrash(t *testing.T) {
	if os.Getenv("RAZVILKA_SELF_UPDATE_CRASH_CHILD") == "1" {
		s, err := Open(os.Getenv("RAZVILKA_TEST_INSTALL"), os.Getenv("RAZVILKA_TEST_JOURNAL"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		s.fault = func(point string) error {
			if point == os.Getenv("RAZVILKA_TEST_CRASH_POINT") {
				os.Exit(86)
			}
			return nil
		}
		f := &fixture{store: s}
		err = perform(f, os.Getenv("RAZVILKA_TEST_OPERATION"), func(context.Context) error {
			return os.WriteFile(filepath.Join(os.Getenv("RAZVILKA_TEST_INSTALL"), "effect-marker"), []byte("once"), 0600)
		})
		t.Fatalf("child did not exit: %v", err)
	}
	for _, item := range []struct{ operation, point string }{{"install", "after:receipt:installing"}, {"install", "after:sync:file:0"}, {"install", "after:rename:file:0"}, {"restore", "after:rename:file:0"}, {"execute", "before:command"}, {"execute", "after:command"}, {"accept", "after:receipt:accepted"}} {
		t.Run(item.operation+"/"+item.point, func(t *testing.T) {
			f := fixtureAt(t, t.TempDir())
			seed(t, f, item.operation)
			f.store.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestFileJournalSubprocessCrash$")
			cmd.Env = append(os.Environ(), "RAZVILKA_SELF_UPDATE_CRASH_CHILD=1", "RAZVILKA_TEST_INSTALL="+f.installation, "RAZVILKA_TEST_JOURNAL="+f.journal, "RAZVILKA_TEST_OPERATION="+item.operation, "RAZVILKA_TEST_CRASH_POINT="+item.point)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 86 {
				t.Fatalf("child crash: %v %s", err, out)
			}
			f.reopen(t)
			r, _, err := f.store.Current()
			if err != nil {
				t.Fatal(err)
			}
			if r.Phase == "accepted" {
				if _, err := os.Stat(filepath.Join(f.journal, transaction, "old-0")); err != nil {
					t.Fatal(err)
				}
				return
			}
			if r.Phase == "command-started" {
				if !errors.Is(f.store.Execute(context.Background(), transaction, "start-candidate", okay, func(context.Context) error { t.Fatal("crashed command replayed"); return nil }), ErrUnknown) {
					t.Fatal("crash lost unknown fence")
				}
				if err := f.store.ResolveUnknown(context.Background(), transaction, okay, okay, okay); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.store.Restore(context.Background(), transaction, okay, okay); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Accept(context.Background(), transaction, true, okay, okay); err != nil {
				t.Fatal(err)
			}
			f.old(t)
		})
	}
}
