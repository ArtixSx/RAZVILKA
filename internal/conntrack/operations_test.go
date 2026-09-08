package conntrack

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/telemetry"
)

func TestCollectorPausesWithoutPublishingFalseFailureAndHoldsReadAdmission(t *testing.T) {
	root := t.TempDir()
	cfg, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "conntrack")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var start, finish sync.Once
	defer finish.Do(func() { close(resume) })
	store := telemetry.NewStore()
	store.SetProducer(true, "kernel-conntrack", "previous confirmed collection")
	prior := store.Status()
	collector := New(store, cfg, func() catalog.Catalog {
		start.Do(func() { close(entered) })
		<-resume
		return catalog.Catalog{}
	})
	collector.ConntrackPaths = []string{path}
	collector.Operations = &operationgate.Gate{}
	release, _ := collector.Operations.Exclusive(context.Background())
	if _, err := collector.Collect(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("collector bypassed restore", err)
	}
	collector.collectAndReport(context.Background())
	if !reflect.DeepEqual(prior, store.Status()) {
		t.Fatal("paused collection published network failure")
	}
	select {
	case <-entered:
		t.Fatal("collector read catalogue during restore")
	default:
	}
	release()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = collector.Collect(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not start")
	}
	if _, err := collector.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("restore overlapped collection")
	}
	finish.Do(func() { close(resume) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not finish")
	}
	last, err := collector.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("collection leaked admission", err)
	}
	last()
}
