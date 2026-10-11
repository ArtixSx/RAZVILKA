package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func TestSelfUpdateInstallerRoleRefusesUnsealedLocalOwnerWithoutBootstrapFallback(t *testing.T) {
	manager := dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, owner := range []*updatecheck.SelfUpdateFileAdapter{nil, {}} {
		if err := bindSelfUpdateInstallerRoles(ctx, manager, owner, strings.Repeat("a", 32)); !errors.Is(err, dataplane.ErrRuntimeInactivity) {
			t.Fatal("unsealed owner acquired an installer classification", err)
		}
	}
	if len(manager.Adapters) != 0 {
		t.Fatal("refused owner reconstructed a runtime participant")
	}
}
