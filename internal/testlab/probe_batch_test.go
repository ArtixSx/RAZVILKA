package testlab

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

type batchRouteProbe func(context.Context, catalog.Service, string) Result

func (probe batchRouteProbe) Probe(ctx context.Context, service catalog.Service, route string) Result {
	return probe(ctx, service, route)
}

type batchTransport func(*http.Request) (*http.Response, error)

func (transport batchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return transport(r)
}

func TestCanceledProbeBatchDoesNotLaunchWaitingScenariosOrReplaceHistory(t *testing.T) {
	const serviceID = "video"
	const scenarios = 9
	service := catalog.Service{ID: serviceID, Name: "Video"}
	for i := range scenarios {
		service.Probes = append(service.Probes, catalog.Probe{ID: fmt.Sprint(i), URL: "https://example.com/", Required: true})
	}
	cat := catalog.Catalog{Services: []catalog.Service{service}}
	for _, tt := range []struct {
		mode, route string
		limit       int
	}{
		{mode: "current", route: "current", limit: 4},
		{mode: "saved-route", route: "direct", limit: 3},
		{mode: "unrecorded-route", route: "direct", limit: 3},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered := make(chan struct{}, scenarios)
			release := make(chan struct{})
			releaseWorkers := sync.OnceFunc(func() { close(release) })
			defer releaseWorkers()
			block := func() {
				entered <- struct{}{}
				<-release
			}
			runner := NewRunner()
			previous := Result{ServiceID: serviceID, Route: tt.route, ScenarioID: "0", HTTPStatus: http.StatusOK}
			runner.latest[resultKey(previous)] = previous
			runner.Client = &http.Client{Transport: batchTransport(func(*http.Request) (*http.Response, error) {
				block()
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			})}
			prober := batchRouteProbe(func(_ context.Context, service catalog.Service, route string) Result {
				block()
				return fakeRouteProber{}.Probe(context.Background(), service, route)
			})
			finished := make(chan []Result, 1)
			go func() {
				switch tt.mode {
				case "current":
					finished <- runner.ProbeCurrent(ctx, cat, nil)
				case "saved-route":
					finished <- runner.ProbeRoutes(ctx, cat, nil, []string{tt.route}, prober)
				case "unrecorded-route":
					finished <- runner.ProbeRoutesUnrecorded(ctx, cat, nil, []string{tt.route}, prober)
				}
			}()
			for range tt.limit {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("worker slots were not filled")
				}
			}
			cancel()
			select {
			case <-finished:
				t.Fatal("the batch returned before its admitted probes released their resources")
			case <-time.After(20 * time.Millisecond):
			}
			releaseWorkers()
			select {
			case rows := <-finished:
				if len(rows) != 0 || len(entered) != 0 {
					t.Fatalf("canceled batch returned %d rows and started %d queued probes", len(rows), len(entered))
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the canceled batch did not join its admitted probes")
			}
			if len(runner.latest) != 1 || runner.latest[resultKey(previous)].HTTPStatus != previous.HTTPStatus {
				t.Fatalf("canceled batch replaced previous observations: %+v", runner.latest)
			}
		})
	}
}

func TestCurrentAndIsolatedBatchesShareRunnerProbeBudget(t *testing.T) {
	const parallel = 4
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video"}}}
	for i := range parallel {
		cat.Services[0].Probes = append(cat.Services[0].Probes, catalog.Probe{ID: fmt.Sprint(i), URL: "https://example.com/"})
	}
	startedCurrent := make(chan struct{}, parallel)
	startedIsolated := make(chan struct{}, parallel)
	release := make(chan struct{})
	releaseCurrent := sync.OnceFunc(func() { close(release) })
	defer releaseCurrent()
	runner := NewRunner()
	runner.Client = &http.Client{Transport: batchTransport(func(*http.Request) (*http.Response, error) {
		startedCurrent <- struct{}{}
		<-release
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})}
	currentDone := make(chan []Result, 1)
	go func() { currentDone <- runner.ProbeCurrent(t.Context(), cat, nil) }()
	for range parallel {
		select {
		case <-startedCurrent:
		case <-time.After(5 * time.Second):
			t.Fatal("current batch did not occupy its slots")
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	prober := batchRouteProbe(func(ctx context.Context, service catalog.Service, route string) Result {
		startedIsolated <- struct{}{}
		return fakeRouteProber{}.Probe(ctx, service, route)
	})
	isolatedDone := make(chan []Result, 1)
	go func() { isolatedDone <- runner.ProbeRoutesUnrecorded(ctx, cat, nil, []string{"direct"}, prober) }()
	select {
	case <-startedIsolated:
		t.Fatal("isolated batch exceeded the shared runner limit")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case rows := <-isolatedDone:
		if len(rows) != 0 || len(startedIsolated) != 0 {
			t.Fatalf("canceled waiter started isolated probes or returned observations: %+v", rows)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the canceled batch waited for another batch to finish")
	}
	releaseCurrent()
	select {
	case rows := <-currentDone:
		if len(rows) != parallel {
			t.Fatalf("canceling the waiter truncated the active batch: %+v", rows)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the active batch did not finish")
	}
}
