package privaterestore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func feedPayload(t *testing.T) privatebackup.Payload {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	m, err := providerfeed.Open(nil, root)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_, err = m.Save(context.Background(), "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.org/private-subscription-token"}, Name: "Подписка", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := m.ExportPrivateIfPresent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := testPayload(t)
	p.SubscriptionSnapshot = snapshot
	if err := privatebackup.Seal(&p); err != nil {
		t.Fatal(err)
	}
	return p
}
func withFeeds(l Layout) Layout {
	l.FeedRoot = filepath.Join(filepath.Dir(l.Config), "feeds")
	return l
}
func seedFeeds(t *testing.T, l Layout) {
	t.Helper()
	if err := os.MkdirAll(l.FeedRoot, 0700); err != nil {
		t.Fatal(err)
	}
}
func TestSubscriptionOnlineOfflineRestoreIsPausedAndLeasedThroughHandover(t *testing.T) {
	for _, online := range []bool{false, true} {
		t.Run(map[bool]string{false: "offline", true: "online"}[online], func(t *testing.T) {
			l := withFeeds(seedLayout(t, t.TempDir()))
			seedFeeds(t, l)
			p := feedPayload(t)
			c, _, err := Open(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var out restorejournal.Outcome
			if online {
				s := liveStores(t, l)
				s.Feeds, err = providerfeed.Open(nil, l.FeedRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Feeds.Close()
				c.StartRuntime()
				c.beforeHandover = func() error {
					if lease, err := s.Feeds.BeginRestore(context.Background()); err == nil {
						lease.Close()
						t.Fatal("feed lease released before handover")
					}
					return nil
				}
				out, err = c.RestoreOnline(context.Background(), p, map[string]bool{"youtube": true}, s)
				if err == nil {
					views := s.Feeds.List()
					if len(views) != 1 || views[0].Enabled || !views[0].NextRefreshAt.IsZero() {
						t.Fatal("restore started a subscription schedule")
					}
				}
			} else {
				out, err = c.RestoreOffline(context.Background(), p, map[string]bool{"youtube": true})
			}
			if err != nil || out != restorejournal.Applied {
				t.Fatal(out, err)
			}
		})
	}
}
func TestSubscriptionFailureRollsBackOtherTargetsWithoutCreatingFeedImage(t *testing.T) {
	l := withFeeds(seedLayout(t, t.TempDir()))
	seedFeeds(t, l)
	before := imagesOnDisk(t, l)
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.beforeWrite = func(id string) error {
		if id == "subscriptions" {
			return errors.New("synthetic feed target failure")
		}
		return nil
	}
	out, err := c.RestoreOffline(context.Background(), feedPayload(t), map[string]bool{"youtube": true})
	if err == nil || out != restorejournal.RolledBack {
		t.Fatal(out, err)
	}
	requireImages(t, l, before)
	if _, err := os.Stat(filepath.Join(l.FeedRoot, providerfeed.FileName)); !os.IsNotExist(err) {
		t.Fatal("failed restore retained feed image")
	}
}
func TestSubscriptionRestoreWrongLiveBindingRefusesAllWrites(t *testing.T) {
	l := withFeeds(seedLayout(t, t.TempDir()))
	seedFeeds(t, l)
	before := imagesOnDisk(t, l)
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := liveStores(t, l)
	other := t.TempDir()
	os.Chmod(other, 0700)
	s.Feeds, err = providerfeed.Open(nil, other)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Feeds.Close()
	c.StartRuntime()
	out, err := c.RestoreOnline(context.Background(), feedPayload(t), map[string]bool{"youtube": true}, s)
	if err == nil || out != restorejournal.Clean {
		t.Fatal("wrong subscription binding accepted", out, err)
	}
	requireImages(t, l, before)
}
func TestSubscriptionRestoreCrashChild(t *testing.T) {
	root := os.Getenv("RAZVILKA_FEED_RESTORE_CHILD")
	if root == "" {
		return
	}
	l := withFeeds(testLayout(root))
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	c.afterWrite = func(id string) {
		if id == "subscriptions" {
			os.Exit(94)
		}
	}
	c.RestoreOffline(context.Background(), feedPayload(t), map[string]bool{"youtube": true})
	t.Fatal("feed crash point not reached")
}
func TestSubscriptionRecoveryAfterProcessCrashRestoresEveryBeforeImage(t *testing.T) {
	l := withFeeds(seedLayout(t, t.TempDir()))
	seedFeeds(t, l)
	before := imagesOnDisk(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSubscriptionRestoreCrashChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_FEED_RESTORE_CHILD="+filepath.Dir(l.Config))
	output, err := cmd.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 94 {
		t.Fatalf("child did not stop at feed write: %v %s", err, output)
	}
	c, out, err := Open(context.Background(), l)
	if err != nil || out != restorejournal.RolledBack {
		t.Fatal(out, err)
	}
	defer c.Close()
	requireImages(t, l, before)
	if _, err := os.Stat(filepath.Join(l.FeedRoot, providerfeed.FileName)); !os.IsNotExist(err) {
		t.Fatal("crashed restore retained feed image")
	}
}
