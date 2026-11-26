package startuptools

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNC1812SelectionFixedChoices(t *testing.T) {
	for _, current := range []bool{false, true} {
		profiles := []profile{stockProfile(), stockPolicyProfile(), managedListProfile(), wgProfile(true, "wireguard"), wgProfile(true, "amneziawg")}
		if current {
			profiles = []profile{nc1812Entware202611Profile(), nc1812Entware202611PolicyProfile(), nc1812Entware202611ManagedListProfile(), nc1812Entware202611WGProfile("wireguard"), nc1812Entware202611WGProfile("amneziawg")}
		}
		for i, want := range profiles {
			got, err := nc1812ProfileForHint(profiles[0].mainSHA, nc1812ToolSet(i))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("wrong fixed selection", i, err)
			}
		}
	}
	for _, digest := range []string{"", "unknown", ubuntuProfile().mainSHA} {
		for set := nc1812BaseTools; set <= nc1812AmneziaWGTools; set++ {
			if _, err := nc1812ProfileForHint(digest, set); err == nil {
				t.Fatal("unknown main selected")
			}
		}
	}
	if _, err := nc1812ProfileForHint(stockProfile().mainSHA, nc1812ToolSet(255)); err == nil {
		t.Fatal("unknown tool set selected")
	}
}

func TestNC1812SelectionSharedFirstBudgetAndLifetime(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	zeroStart := time.Now()
	hint, hintDone := acquisitionContext(lifetime, time.Time{})
	zeroEnd := time.Now()
	deadline, ok := hint.Deadline()
	if !ok || deadline.Before(zeroStart.Add(operationTimeout)) || deadline.After(zeroEnd.Add(operationTimeout)) {
		t.Fatal("unbounded hint")
	}
	full, fullDone := acquisitionContext(lifetime, deadline)
	defer fullDone()
	fullDeadline, _ := full.Deadline()
	if fullDeadline != deadline {
		t.Fatal("chosen acquisition renewed first budget")
	}
	hintDone()
	if lifetime.Err() != nil || full.Err() != nil {
		t.Fatal("hint became lease lifetime")
	}
	expired, expiredDone := acquisitionContext(lifetime, time.Now().Add(-time.Second))
	defer expiredDone()
	if !errors.Is(expired.Err(), context.DeadlineExceeded) {
		t.Fatal("consumed hint budget renewed")
	}
	start := time.Now()
	later, laterDone := acquisitionContext(lifetime, start.Add(time.Hour))
	defer laterDone()
	laterDeadline, _ := later.Deadline()
	if laterDeadline.After(time.Now().Add(operationTimeout)) || laterDeadline.Before(start) {
		t.Fatal("caller extended cap")
	}
	parent, parentDone := context.WithDeadline(lifetime, start.Add(time.Second))
	defer parentDone()
	child, childDone := acquisitionContext(parent, deadline)
	defer childDone()
	childDeadline, _ := child.Deadline()
	if childDeadline != start.Add(time.Second) {
		t.Fatal("parent deadline lost")
	}
	stop()
	if !errors.Is(full.Err(), context.Canceled) {
		t.Fatal("original lifetime cancellation lost")
	}
}

func TestNC1812SelectionPublicFactoriesRefuseMissingAuthority(t *testing.T) {
	for _, acquire := range []func(context.Context, *netidentity.Provider) (*Lease, error){AcquireReviewedNC1812, AcquireReviewedNC1812Policy, AcquireReviewedNC1812ManagedList, AcquireReviewedNC1812WireGuard, AcquireReviewedNC1812AmneziaWG} {
		if lease, err := acquire(nil, nil); lease != nil || err == nil {
			t.Fatal("missing authority admitted")
		}
		if lease, err := acquire(context.Background(), nil); lease != nil || err == nil {
			t.Fatal("missing provider admitted")
		}
	}
}
