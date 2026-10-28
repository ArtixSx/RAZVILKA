package dataplane

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOriginalProcessRejectsReconstructionAndUnboundedCleanup(t *testing.T) {
	for _, p := range []*OriginalProcess{nil, {}, {done: make(chan struct{}), gate: make(chan struct{}, 1)}} {
		if p.StopAndJoin(context.Background()) == nil {
			t.Fatal("reconstructed token granted cleanup")
		}
	}
	root := t.TempDir()
	spec := ProcessSpec{ID: "fixture", Binary: "must-not-start", Dir: root, PIDPath: filepath.Join(root, "engine.pid"),
		LogPath: filepath.Join(root, "engine.log"), MatchArg: filepath.Join(root, "engine.json"), RouteProof: true}
	if _, err := (OSProcessController{}).StartOriginal(context.Background(), spec, "127.0.0.1:19000"); err == nil {
		t.Fatal("unbounded original launch accepted")
	}
}
