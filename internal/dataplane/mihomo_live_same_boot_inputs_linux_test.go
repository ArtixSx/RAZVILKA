//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// Actual private journal locks and protected files. The historical runtime
// definition is modeled comparison data; these tests issue no native permit.
func sameBootInputsFixture(t *testing.T, use func(context.Context, *privaterestore.OfflineServiceControlSet, string, Execution)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	base := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	l := privaterestore.Layout{Config: filepath.Join(base, "config.json"), CustomServices: filepath.Join(base, "custom.json"), Devices: filepath.Join(base, "devices.json"), StageRoot: filepath.Join(base, "stage"), ProviderRoot: filepath.Join(base, "provider")}
	var cs []*privaterestore.Coordinator
	defer func() {
		for n := len(cs) - 1; n >= 0; n-- {
			if err := cs[n].Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	for n, name := range []string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1", "private-restore-strategylab-v1"} {
		l.JournalRoot = filepath.Join(base, name)
		if n >= 1 {
			l.NodeRoot = filepath.Join(base, "nodes")
		}
		if n >= 2 {
			l.WarpRoot = filepath.Join(base, "warp")
		}
		if n >= 3 {
			l.FeedRoot = filepath.Join(base, "subscriptions-private")
		}
		if n >= 4 {
			l.StrategyLabPath = filepath.Join(base, "strategy-lab.json")
		}
		seed, _, err := privaterestore.Open(ctx, l)
		if err != nil {
			t.Fatal(err)
		}
		if err := seed.Close(); err != nil {
			t.Fatal(err)
		}
		c, err := privaterestore.OpenForOfflineServiceControl(ctx, l)
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	if err := os.WriteFile(l.Config, []byte("{\"revision\":1}"), 0600); err != nil {
		t.Fatal(err)
	}
	e := mihomoColdIntentFixture(t)
	e.State = "committed"
	e.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	for n := range e.Steps {
		e.Steps[n].State = "passed"
		e.Steps[n].FinishedAt = e.FinishedAt
	}
	e.Resources[0].State = "active"
	e.Resources[0].Phase = "active"
	e.Resources[0].MihomoLive.Observation = &MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: strings.Repeat("a", 64)}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "dataplane")
	if err := os.MkdirAll(filepath.Join(state, "transactions", e.PlanID), 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"latest-execution.json", filepath.Join("transactions", e.PlanID, "execution.json")} {
		if err := os.WriteFile(filepath.Join(state, p), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := privaterestore.WithOfflineServiceControlSet(ctx, l.Config, cs, func(c context.Context, s *privaterestore.OfflineServiceControlSet) error {
		for _, p := range []string{state, filepath.Dir(l.Config)} {
			info, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			if !proxyInactivePrivateDirectory(info) {
				t.Fatalf("fixture original root is not private: mode=%v uid=%d euid=%d", info.Mode(), info.Sys().(*syscall.Stat_t).Uid, os.Geteuid())
			}
		}
		use(c, s, state, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMihomoSameBootInputsRetainOriginalFiles(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, s *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, s, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		if err := i.current(ctx); err != nil {
			t.Fatal(err)
		}
		copy := &mihomoSameBootInputs{self: i, ctx: ctx, private: s, roots: i.roots, infos: i.infos, paths: i.paths, records: i.records}
		if copy.current(ctx) == nil || copy.close() == nil {
			t.Fatal("copied owner accepted")
		}
		if err := i.current(ctx); err != nil {
			t.Fatal("copy retired original", err)
		}
		if i.current(context.WithValue(ctx, struct{}{}, true)) == nil {
			t.Fatal("foreign context accepted")
		}
		if err := i.close(); err != nil {
			t.Fatal(err)
		}
		if i.current(ctx) == nil {
			t.Fatal("closed owner revived")
		}
	})
}

func TestMihomoSameBootInputsRefuseEqualByteReplacement(t *testing.T) {
	for _, which := range []string{"config", "latest", "transaction", "root"} {
		t.Run(which, func(t *testing.T) {
			sameBootInputsFixture(t, func(ctx context.Context, s *privaterestore.OfflineServiceControlSet, state string, e Execution) {
				i, err := holdMihomoSameBootInputs(ctx, s, state, e.PlanID, e.Digest)
				if err != nil {
					t.Fatal(err)
				}
				defer i.close()
				if which == "root" {
					if err := os.Rename(state, state+"-old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(state, 0700); err != nil {
						t.Fatal(err)
					}
				} else {
					r := i.records[0]
					if which == "config" {
						r = i.records[2]
					}
					if which == "latest" {
						r = i.records[1]
					}
					temp := r.name + ".foreign"
					if err := r.root.WriteFile(temp, r.data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := r.root.Rename(temp, r.name); err != nil {
						t.Fatal(err)
					}
				}
				if i.current(ctx) == nil {
					t.Fatal("foreign equal-byte inode accepted")
				}
			})
		})
	}
}

func TestMihomoSameBootInputsRetainStickyCloseCause(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, s *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, s, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := i.records[0].file.Close(); err != nil {
			t.Fatal(err)
		}
		first := i.close()
		if first == nil || !errors.Is(i.close(), os.ErrClosed) || !errors.Is(i.current(ctx), os.ErrClosed) {
			t.Fatal("original close exception hidden", first)
		}
	})
}

func TestMihomoSameBootInputsRefuseSpecialConfigurationWithoutBlocking(t *testing.T) {
	for _, which := range []string{"fifo", "symlink", "oversized"} {
		t.Run(which, func(t *testing.T) {
			sameBootInputsFixture(t, func(ctx context.Context, s *privaterestore.OfflineServiceControlSet, state string, e Execution) {
				path, err := s.ConfigurationPath(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch which {
				case "fifo":
					if err := syscall.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(filepath.Join(state, "latest-execution.json"), path); err != nil {
						t.Fatal(err)
					}
				case "oversized":
					f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
					if err != nil {
						t.Fatal(err)
					}
					if err := f.Truncate((4 << 20) + 1); err != nil {
						t.Fatal(err)
					}
					if err := f.Close(); err != nil {
						t.Fatal(err)
					}
				}
				started := time.Now()
				i, err := holdMihomoSameBootInputs(ctx, s, state, e.PlanID, e.Digest)
				if i != nil || err == nil {
					if i != nil {
						_ = i.close()
					}
					t.Fatal("special/oversized config admitted", which)
				}
				if time.Since(started) > time.Second {
					t.Fatal("configuration observation blocked", which)
				}
			})
		})
	}
}
