package dataplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Protocol/lifecycle models only. These runners issue no protected source,
// actual kernel inventory or execution authority.
type backendInventoryObserverModel struct {
	backendInventoryTestRunner
	observe func(context.Context, netidentity.Identity, string, func(context.Context) error) error
}

func (m backendInventoryObserverModel) WithReadOnlyToolObservation(c context.Context, id netidentity.Identity, review string, use func(context.Context) error) error {
	return m.observe(c, id, review, use)
}

func TestBackendInventoryObservationKeepsEveryKernelAndToolBookend(t *testing.T) {
	r, scope, p, nft, order := backendInventoryTestFixture(t)
	base := r.Runner.(backendInventoryTestRunner)
	opening, closing := 0, 0
	r.Runner = backendInventoryObserverModel{backendInventoryTestRunner: base, observe: func(ctx context.Context, id netidentity.Identity, review string, use func(context.Context) error) error {
		if id != scope.Network || review != scope.ToolReviewID {
			return errors.New("original source identity changed")
		}
		opening++
		err := use(ctx)
		closing++
		return err
	}}
	view, err := r.read(context.Background(), scope, p)
	if err != nil || view.requireLANBackendCoverage() != nil || len(view.Rows) != 10 || opening != 1 || closing != 1 || nft.generationCalls != 2 || nft.closed != 1 {
		t.Fatal("original full collector bookends changed", opening, closing, nft.generationCalls, nft.closed, err)
	}
	tools, names, reads := 0, 0, 0
	for _, event := range *order {
		switch {
		case event == "tools":
			tools++
		case strings.HasPrefix(event, "names"):
			names++
		case strings.HasPrefix(event, r.IPTables+":") || strings.HasPrefix(event, r.IP6Tables+":"):
			reads++
		}
	}
	if tools != 2 || names != 8 || reads != 20 {
		t.Fatal("kernel/tool reads skipped", tools, names, reads, *order)
	}
}

func TestBackendInventoryObservationRejectsBadOwnerLifecycle(t *testing.T) {
	for _, kind := range []string{"no-use", "duplicate", "closing-error", "callback-error", "late", "longer-context"} {
		t.Run(kind, func(t *testing.T) {
			r, scope, p, nft, _ := backendInventoryTestFixture(t)
			base := r.Runner.(backendInventoryTestRunner)
			original := errors.New("original source closing error")
			var escaped func(context.Context) error
			r.Runner = backendInventoryObserverModel{backendInventoryTestRunner: base, observe: func(ctx context.Context, _ netidentity.Identity, _ string, use func(context.Context) error) error {
				switch kind {
				case "no-use":
					return nil
				case "late":
					escaped = use
					return nil
				case "longer-context":
					return use(context.Background())
				}
				err := use(ctx)
				if kind == "duplicate" {
					_ = use(ctx)
				}
				if kind == "closing-error" {
					return errors.Join(err, original)
				}
				return nil // Deliberately ignore the callback error: collector must retain it.
			}}
			if kind == "callback-error" {
				p.registeredTables = func(context.Context, int) ([]byte, error) { return nil, original }
			}
			view, err := r.read(context.Background(), scope, p)
			if err == nil || len(view.Rows) != 0 || view.requireLANBackendCoverage() == nil {
				t.Fatal("invalid owner returned positive inventory", view, err)
			}
			if (kind == "closing-error" || kind == "callback-error") && !errors.Is(err, original) {
				t.Fatal("original exception lost", err)
			}
			if escaped != nil {
				before := nft.generationCalls
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if escaped(ctx) == nil || nft.generationCalls != before {
					t.Fatal("expired callback ran kernel reads")
				}
			}
		})
	}
}

func TestBackendInventoryObservationCancelsAndJoinsEarlyReturn(t *testing.T) {
	r, scope, p, nft, _ := backendInventoryTestFixture(t)
	entered, finished := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.Runner = backendInventoryObserverModel{backendInventoryTestRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}, observe: func(ctx context.Context, _ netidentity.Identity, _ string, use func(context.Context) error) error {
		go func() { defer close(finished); _ = use(ctx) }()
		select {
		case <-entered:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	view, err := r.read(ctx, scope, p)
	if !errors.Is(err, context.Canceled) || len(view.Rows) != 0 || nft.closed != 1 {
		t.Fatal("unjoined or successful premature source", view, nft.closed, err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("original in-flight reader not joined")
	}
}
