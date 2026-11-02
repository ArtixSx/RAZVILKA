package privaterestore

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func strategyPayload(t *testing.T) privatebackup.Payload {
	t.Helper()
	m, err := strategylab.New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.AddCandidate("tcp-tls", "archive candidate", "--filter-tcp=443", "manual"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := m.ExportPrivateIfPresent(context.Background())
	if err != nil || snapshot == nil {
		t.Fatal("missing exported StrategyLab state", err)
	}
	p := testPayload(t)
	p.StrategyLabSnapshot = snapshot
	if err := privatebackup.Seal(&p); err != nil {
		t.Fatal(err)
	}
	return p
}
func withStrategy(l Layout) Layout {
	l.StrategyLabPath = filepath.Join(filepath.Dir(l.Config), "strategy-lab.json")
	return l
}

func TestStrategyLabOnlineOfflineRestoreAndHandover(t *testing.T) {
	for _, online := range []bool{false, true} {
		t.Run(map[bool]string{false: "offline", true: "online"}[online], func(t *testing.T) {
			l := withStrategy(seedLayout(t, t.TempDir()))
			c, _, err := Open(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			p := strategyPayload(t)
			var out restorejournal.Outcome
			if online {
				s := liveStores(t, l)
				s.StrategyLab, err = strategylab.New(l.StrategyLabPath)
				if err != nil {
					t.Fatal(err)
				}
				if err = c.StartRuntime(); err != nil {
					t.Fatal(err)
				}
				c.beforeHandover = func() error {
					if lease, err := s.StrategyLab.BeginRestore(context.Background()); err == nil {
						lease.Close()
						t.Fatal("StrategyLab lease released before handover")
					}
					return nil
				}
				out, err = c.RestoreOnline(context.Background(), p, map[string]bool{"youtube": true}, s)
				if err == nil && len(s.StrategyLab.Snapshot().Candidates) != 1 {
					t.Fatal("live cache not handed over")
				}
			} else {
				out, err = c.RestoreOffline(context.Background(), p, map[string]bool{"youtube": true})
			}
			if err != nil || out != restorejournal.Applied {
				t.Fatal(out, err)
			}
			m, err := strategylab.New(l.StrategyLabPath)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := m.Snapshot()
			if len(snapshot.Candidates) != 1 || snapshot.Candidates[0].Validation.OK {
				t.Fatal("candidate lost or validation authority restored")
			}
		})
	}
}
func TestStrategyLabWrongLiveBindingRefusesAllWrites(t *testing.T) {
	l := withStrategy(seedLayout(t, t.TempDir()))
	before := imagesOnDisk(t, l)
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := liveStores(t, l)
	s.StrategyLab, err = strategylab.New(filepath.Join(t.TempDir(), "other.json"))
	if err != nil {
		t.Fatal(err)
	}
	c.StartRuntime()
	out, err := c.RestoreOnline(context.Background(), strategyPayload(t), map[string]bool{"youtube": true}, s)
	if err == nil || out != restorejournal.Clean {
		t.Fatal("wrong binding accepted", out, err)
	}
	requireImages(t, l, before)
}
func TestStrategyLabCrashChild(t *testing.T) {
	root := os.Getenv("RAZVILKA_STRATEGY_RESTORE_CHILD")
	if root == "" {
		return
	}
	l := withStrategy(testLayout(root))
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	c.afterWrite = func(id string) {
		if id == os.Getenv("RAZVILKA_STRATEGY_CRASH_SLOT") {
			os.Exit(95)
		}
	}
	c.RestoreOffline(context.Background(), strategyPayload(t), map[string]bool{"youtube": true})
	t.Fatal("crash point not reached")
}
func TestStrategyLabRecoveryAfterCrashRestoresEveryBeforeImage(t *testing.T) {
	for _, slot := range []string{"config", "strategy_lab"} {
		t.Run(slot, func(t *testing.T) {
			l := withStrategy(seedLayout(t, t.TempDir()))
			before := imagesOnDisk(t, l)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStrategyLabCrashChild$")
			cmd.Env = append(os.Environ(), "RAZVILKA_STRATEGY_RESTORE_CHILD="+filepath.Dir(l.Config), "RAZVILKA_STRATEGY_CRASH_SLOT="+slot)
			output, err := cmd.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 95 {
				t.Fatalf("child did not stop after %s write: %v %s", slot, err, output)
			}
			c, out, err := Open(context.Background(), l)
			if err != nil || out != restorejournal.RolledBack {
				t.Fatal(out, err)
			}
			defer c.Close()
			requireImages(t, l, before)
			if _, err := os.Stat(l.StrategyLabPath); !os.IsNotExist(err) {
				t.Fatal("crashed restore retained state", err)
			}
		})
	}
}
func TestStrategyLabOptionalLayoutPreservesLegacyScopeAndRejectsOverlap(t *testing.T) {
	l := testLayout(t.TempDir())
	_, legacy, err := normalizeLayout(l)
	if err != nil {
		t.Fatal(err)
	}
	with := withStrategy(l)
	_, current, err := normalizeLayout(with)
	if err != nil || legacy == current {
		t.Fatal("StrategyLab path absent from journal binding", err)
	}
	for _, path := range []string{l.Config, l.JournalRoot, filepath.Join(l.StageRoot, "state.json")} {
		with.StrategyLabPath = path
		if _, _, err := normalizeLayout(with); err == nil {
			t.Fatal("overlapping strategy path accepted")
		}
	}
}
