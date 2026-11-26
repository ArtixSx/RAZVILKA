package privaterestore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func nodePayload(t *testing.T, root string) privatebackup.Payload {
	t.Helper()
	path := filepath.Join(root, "archive-fixture")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := nodestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@fixture.example:443?security=tls", time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := testPayload(t)
	p.NodeSnapshot = &nodes
	if err := privatebackup.Seal(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func withNodeRoot(t *testing.T, l Layout) Layout {
	t.Helper()
	l.NodeRoot = filepath.Join(filepath.Dir(l.Config), "nodes")
	if err := os.Mkdir(l.NodeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNodeOfflineAndOnlineRestoreIntegration(t *testing.T) {
	for _, online := range []bool{false, true} {
		t.Run(map[bool]string{false: "offline", true: "online"}[online], func(t *testing.T) {
			root := t.TempDir()
			l := withNodeRoot(t, seedLayout(t, root))
			p := nodePayload(t, root)
			c, _, err := Open(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var s Stores
			if online {
				s = liveStores(t, l)
				s.Nodes, err = nodestore.Open(l.NodeRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Nodes.Close()
				if err := c.StartRuntime(); err != nil {
					t.Fatal(err)
				}
				c.beforeHandover = func() error {
					if other, err := s.Nodes.BeginRestore(context.Background()); err == nil {
						other.Close()
						t.Fatal("node session released before handover")
					}
					return nil
				}
			}
			var out restorejournal.Outcome
			if online {
				out, err = c.RestoreOnline(context.Background(), p, map[string]bool{"youtube": true}, s)
			} else {
				out, err = c.RestoreOffline(context.Background(), p, map[string]bool{"youtube": true})
			}
			if err != nil || out != restorejournal.Applied {
				t.Fatalf("outcome %s err %v", out, err)
			}
			if !online {
				s.Nodes, err = nodestore.Open(l.NodeRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Nodes.Close()
			}
			snap, err := s.Nodes.Snapshot(context.Background(), time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC))
			if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].State != "expired" || snap.Nodes[0].Health.State != "not_checked" {
				t.Fatal("node restore lost data or refreshed health")
			}
		})
	}
}

func TestNodeRestoreRollsBackAlongsideOtherTargets(t *testing.T) {
	root := t.TempDir()
	l := withNodeRoot(t, seedLayout(t, root))
	p := nodePayload(t, root)
	before := imagesOnDisk(t, l)
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := liveStores(t, l)
	s.Nodes, err = nodestore.Open(l.NodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Nodes.Close()
	c.StartRuntime()
	failed := false
	c.beforeWrite = func(id string) error {
		if id == "provider_cloudflare" && !failed {
			failed = true
			return errors.New("injected after nodes")
		}
		return nil
	}
	out, err := c.RestoreOnline(context.Background(), p, map[string]bool{"youtube": true}, s)
	if err == nil || out != restorejournal.RolledBack {
		t.Fatalf("outcome %s err %v", out, err)
	}
	requireImages(t, l, before)
	snap, err := s.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || len(snap.Nodes) != 0 {
		t.Fatal("nodes survived rollback of absent target")
	}
	if _, err := os.Stat(filepath.Join(l.NodeRoot, "nodes.private.json")); !os.IsNotExist(err) {
		t.Fatal("absent node image not restored")
	}
}

func TestNodeRestoreRejectsMissingTargetAndWrongBindingBeforeWrites(t *testing.T) {
	root := t.TempDir()
	l := seedLayout(t, root)
	p := nodePayload(t, root)
	before := imagesOnDisk(t, l)
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RestoreOffline(context.Background(), p, map[string]bool{"youtube": true}); err == nil {
		t.Fatal("node archive silently ignored")
	}
	requireImages(t, l, before)
	c.Close()
	// A distinct journal directory is intentional: changing the trusted scope
	// of an existing journal is NOT a supported migration.
	l.JournalRoot = filepath.Join(root, "node-journal")
	l = withNodeRoot(t, l)
	c, _, err = Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := liveStores(t, l)
	wrong := filepath.Join(root, "wrong-nodes")
	os.Mkdir(wrong, 0o700)
	s.Nodes, err = nodestore.Open(wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Nodes.Close()
	c.StartRuntime()
	out, err := c.RestoreOnline(context.Background(), p, map[string]bool{"youtube": true}, s)
	if err == nil || out != restorejournal.Clean {
		t.Fatal("wrong node store binding accepted")
	}
	requireImages(t, l, before)
}

func TestNodeLayoutBoundary(t *testing.T) {
	l := testLayout(t.TempDir())
	for _, invalid := range []string{l.ProviderRoot, filepath.Dir(l.Config), filepath.Join(l.StageRoot, "nodes"), l.Config} {
		l.NodeRoot = invalid
		if _, _, err := normalizeLayout(l); err == nil {
			t.Fatal("overlapping node root accepted")
		}
	}
}

func TestEnablingNodeRootDoesNotRebindExistingJournal(t *testing.T) {
	root := t.TempDir()
	legacy := seedLayout(t, root)
	c, out, err := Open(context.Background(), legacy)
	if err != nil || out != restorejournal.Clean {
		t.Fatalf("create legacy coordinator: %s %v", out, err)
	}
	out, err = c.RestoreOffline(context.Background(), testPayload(t), map[string]bool{"youtube": true})
	if err != nil || out != restorejournal.Applied {
		t.Fatalf("create legacy idle journal: %s %v", out, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	legacy.NodeRoot = filepath.Join(root, "nodes")
	if err := os.Mkdir(legacy.NodeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if c, out, err := Open(context.Background(), legacy); err == nil || out != restorejournal.Blocked || c != nil {
		if c != nil {
			c.Close()
		}
		t.Fatalf("changed trusted scope accepted: %s %v", out, err)
	}
}

func TestNodeRecoveryProcessHelper(t *testing.T) {
	root := os.Getenv("RAZVILKA_NODE_COORDINATOR_CRASH")
	if root == "" {
		t.Skip("subprocess helper")
	}
	l := testLayout(root)
	l.NodeRoot = filepath.Join(root, "nodes")
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("RAZVILKA_NODE_COORDINATOR_PHASE") == "committed" {
		s := liveStores(t, l)
		s.Nodes, err = nodestore.Open(l.NodeRoot)
		if err != nil {
			t.Fatal(err)
		}
		c.StartRuntime()
		c.beforeHandover = func() error { os.Exit(74); return nil }
		_, _ = c.RestoreOnline(context.Background(), nodePayload(t, root), map[string]bool{"youtube": true}, s)
	} else {
		c.afterWrite = func(id string) {
			if id == "nodes" {
				os.Exit(73)
			}
		}
		_, _ = c.RestoreOffline(context.Background(), nodePayload(t, root), map[string]bool{"youtube": true})
	}
	t.Fatal("node crash hook not reached")
}

func TestNodeStartupRecoveryAfterProcessDeath(t *testing.T) {
	for _, phase := range []string{"prepared", "committed"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			l := withNodeRoot(t, seedLayout(t, root))
			before := imagesOnDisk(t, l)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodeRecoveryProcessHelper$")
			cmd.Env = append(os.Environ(), "RAZVILKA_NODE_COORDINATOR_CRASH="+root, "RAZVILKA_NODE_COORDINATOR_PHASE="+phase)
			err := cmd.Run()
			var exit *exec.ExitError
			wantExit := 73
			wantOutcome := restorejournal.RolledBack
			if phase == "committed" {
				wantExit = 74
				wantOutcome = restorejournal.Applied
			}
			if !errors.As(err, &exit) || exit.ExitCode() != wantExit {
				t.Fatal("child did not reach node write crash point")
			}
			c, out, err := Open(context.Background(), l)
			if err != nil || out != wantOutcome {
				t.Fatalf("recovery %s err %v", out, err)
			}
			defer c.Close()
			if phase == "prepared" {
				requireImages(t, l, before)
				if _, err := os.Stat(filepath.Join(l.NodeRoot, "nodes.private.json")); !os.IsNotExist(err) {
					t.Fatal("startup recovery left new nodes")
				}
			} else {
				s, err := nodestore.Open(l.NodeRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				snap, err := s.Snapshot(context.Background(), time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC))
				if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].State != "expired" || snap.Nodes[0].Health.State != "not_checked" {
					t.Fatal("committed startup recovery lost nodes or promoted health")
				}
			}
		})
	}
}
