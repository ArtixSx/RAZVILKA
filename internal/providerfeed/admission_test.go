package providerfeed

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func awaitFeedSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("feed did not reach expected boundary")
	}
}

type feedCloseSignal struct {
	io.ReadCloser
	closed chan struct{}
}

func (b feedCloseSignal) Close() error {
	err := b.ReadCloser.Close()
	close(b.closed)
	return err
}

func TestManagedFeedReleasesDownloadButReacquiresBeforeImport(t *testing.T) {
	for _, action := range []string{"commit", "cancel", "disable", "delete", "restore", "fence", "fetch-failure"} {
		t.Run(action, func(t *testing.T) {
			m, nodes, _ := persistentManager(t)
			var clockOffset atomic.Int64
			m.now = func() time.Time { return testTime.Add(time.Duration(clockOffset.Load())) }
			feed := saveFeed(t, m, true)
			var gate operationgate.Gate
			ctx, stop := context.WithCancel(context.Background())
			defer func() {
				stop()
				wait, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := m.Wait(wait); err != nil {
					t.Error(err)
				}
			}()
			fetching, respond, closed, waiting := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				close(fetching)
				select {
				case <-respond:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
				code := http.StatusOK
				if action == "fetch-failure" {
					code = http.StatusServiceUnavailable
				}
				resp := response(code, goodURI, nil)
				resp.Body = feedCloseSignal{resp.Body, closed}
				return resp, nil
			})}
			m.StartManaged(ctx, func(ctx context.Context) (func(), error) {
				release, err := gate.Enter(ctx)
				if errors.Is(err, operationgate.ErrBusy) {
					once.Do(func() { close(waiting) })
				}
				return release, err
			})
			job, err := m.QueueSync(feed.SourceID)
			if err != nil {
				t.Fatal(err)
			}
			awaitFeedSignal(t, fetching)
			// This is the same gate that protects real application restore/Stop.
			release, err := gate.Exclusive(context.Background())
			if err != nil {
				t.Fatal("network fetch retained application admission", err)
			}
			defer release()
			close(respond)
			awaitFeedSignal(t, closed)
			awaitFeedSignal(t, waiting)
			// The importer must wait without holding m.mu; user edits remain usable.
			if !m.mu.TryLock() {
				t.Fatal("waiting worker retained manager mutex")
			}
			pending, err := m.storage.target.Read(context.Background())
			m.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			view, err := nodes.Snapshot(context.Background(), testTime)
			if err != nil || len(view.Nodes) != 0 {
				t.Fatal("import bypassed exclusive operation")
			}
			inflight, _ := m.Job(job.ID)
			if inflight.Status != "running" {
				t.Fatal("worker finished before admission")
			}
			wantStatus, wantCode := "failed", "FEED_CHANGED"
			switch action {
			case "commit":
				wantStatus, wantCode = "completed", ""
				clockOffset.Store(int64(time.Minute))
			case "cancel":
				_, err = m.CancelJob(job.ID)
				wantStatus, wantCode = "canceled", "FEED_CANCELED"
			case "disable":
				_, err = m.Save(context.Background(), feed.SourceID, SaveRequest{Request: Request{URL: "https://feed.example.org/private-path-token?secret=query-token", Limit: 128}, Enabled: false, Revision: feed.Revision})
			case "delete":
				err = m.Delete(context.Background(), feed.SourceID, feed.Revision)
			case "restore":
				var target *RestoreTarget
				target, err = m.BeginRestore(context.Background())
				if err == nil {
					err = target.Close()
				}
				// Even the same image/source revision invalidates an earlier fetch.
			case "fence":
				gate.Fence()
				wantCode = "FEED_RECOVERY"
			case "fetch-failure":
				wantCode = "FEED_FETCH"
			}
			if err != nil {
				t.Fatal(err)
			}
			if action != "cancel" {
				release()
			}
			done := waitJob(t, m, job.ID)
			if done.Status != wantStatus || done.ErrorCode != wantCode {
				t.Fatalf("job state=%s code=%s", done.Status, done.ErrorCode)
			}
			view, err = nodes.Snapshot(context.Background(), testTime)
			wantCount := 0
			if action == "commit" {
				wantCount = 1
			}
			if err != nil || len(view.Nodes) != wantCount {
				t.Fatal("wrong imported count")
			}
			if action == "commit" && !done.Result.OriginExpiresAt.Equal(testTime.Add(OriginTTL)) {
				t.Fatal("admission waiting extended origin lifetime")
			}
			if action == "cancel" || action == "fence" || action == "restore" {
				after, err := m.storage.target.Read(context.Background())
				if err != nil || !bytes.Equal(pending.Data, after.Data) {
					t.Fatal("interrupted response changed durable reservation")
				}
				if m.List()[0].Status != "interrupted" {
					t.Fatal("interrupted fetch still shown as downloading")
				}
			}
		})
	}
}

func TestManagedFeedCancellationJoinsTransportCleanup(t *testing.T) {
	m, _, _ := persistentManager(t)
	feed := saveFeed(t, m, true)
	var gate operationgate.Gate
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	started, canceled, cleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(cleanup) })
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		close(canceled)
		<-cleanup
		return nil, r.Context().Err()
	})}
	m.StartManaged(ctx, gate.Enter)
	job, err := m.QueueSync(feed.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	awaitFeedSignal(t, started)
	if _, err = m.CancelJob(job.ID); err != nil {
		t.Fatal(err)
	}
	awaitFeedSignal(t, canceled)
	current, _ := m.Job(job.ID)
	if current.Status != "running" {
		t.Fatal("job falsely finished before cleanup")
	}
	if duplicate, err := m.QueueSync(feed.SourceID); err != nil || duplicate.ID != job.ID {
		t.Fatal("cancel opened a second fetch")
	}
	release, err := gate.Exclusive(context.Background())
	if err != nil {
		t.Fatal("cleanup blocks application")
	}
	defer release()
	once.Do(func() { close(cleanup) })
	if done := waitJob(t, m, job.ID); done.Status != "canceled" {
		t.Fatal(done.Status)
	}
	stop()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = m.Wait(wait); err != nil {
		t.Fatal(err)
	}
}

func TestOneShotPreparedFeedCannotOverwriteNewSavedConsent(t *testing.T) {
	m, nodes, _ := persistentManager(t)
	var gate operationgate.Gate
	started, respond := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		select {
		case <-respond:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return response(200, goodURI, nil), nil
	})}
	done := make(chan error, 1)
	go func() {
		_, err := m.SyncWithAdmission(ctx, Request{URL: "https://feed.example.org/private-path-token?secret=query-token", Limit: 128}, gate.Enter)
		done <- err
	}()
	awaitFeedSignal(t, started)
	release, err := gate.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	saved := saveFeed(t, m, false)
	release()
	close(respond)
	if err = <-done; !errors.Is(err, ErrConflict) {
		t.Fatal("one-shot response replaced saved consent", err)
	}
	current, err := m.Saved(saved.SourceID)
	if err != nil || current.Enabled || current.Status != "saved" || current.Revision != saved.Revision {
		t.Fatal("saved consent changed")
	}
	view, err := nodes.Snapshot(ctx, testTime)
	if err != nil || len(view.Nodes) != 0 {
		t.Fatal("outdated one-shot response imported")
	}
}
