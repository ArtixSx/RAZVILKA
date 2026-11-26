package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestExternalBootstrapOfflinePreservesIntentWithoutAnyLiveGrant(t *testing.T) {
	for _, kind := range []string{"stopped", "safe-mode", "both"} {
		t.Run(kind, func(t *testing.T) {
			a, u, review := bootstrapOwnerFixture(t)
			review.Bootstrap.Mode = "offline"
			cfg := config.Config{Revision: 7}
			cfg.ServiceControl.Stopped = kind != "safe-mode"
			cfg.SafeMode = kind != "stopped"
			old, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			sealFileExclusionFixture(t, a, u, review, old, append(append([]byte(nil), old...), '\n'))
			if err := a.Authority(context.Background(), review.ID, 7); err != nil {
				t.Fatal("file-only authority required old routes to run", err)
			}
			for _, action := range []string{"start/live", "stop-owned", "replace-to-rollback"} {
				if a.AuthorityAction(context.Background(), review.ID, 7, action) == nil {
					t.Fatal("offline review granted generic action", action)
				}
			}
			for _, command := range []string{"start-candidate-panel", "start-rollback-panel", "restore-private-state"} {
				if fileCommandAuthorityForReview(review, command) == bootstrapOfflineAction {
					t.Fatal("file-only mode accepted runtime start/restore", command)
				}
			}
			for _, effect := range []string{"command-worker-start-candidate-panel", "command-child-start-rollback-panel", "paired-retire-paired-receipt", "rollback-file-0"} {
				if validFileEffectAction(effect, bootstrapOfflineAction) {
					t.Fatal("file-only action accepted unrelated effect", effect)
				}
			}
			for _, effect := range []string{"install-file-0", pairedPriorManifestEffect, "paired-seal-paired-receipt", "command-worker-quiesce-old-runtime"} {
				if !validFileEffectAction(effect, bootstrapOfflineAction) {
					t.Fatal("fixed offline plan effect missing", effect)
				}
			}
			a.stopCheck = func(context.Context, string) (bool, error) { return true, nil }
			if !errors.Is(a.Authority(context.Background(), review.ID, 7), ErrFileAuthorityStopped) {
				t.Fatal("file-only bootstrap cleared/bypassed modern durable Stop")
			}
		})
	}
}

func TestExternalBootstrapOfflineMigrationCannotEnableRoutesOrDropStop(t *testing.T) {
	before := config.Config{Revision: 7, SafeMode: true}
	before.ServiceControl.Stopped = true
	old, _ := json.Marshal(before)
	if _, err := inspectFileMigrationMode(old, append(append([]byte(nil), old...), '\n'), 7, true); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"safe", "stopped", "revision"} {
		after := before
		switch kind {
		case "safe":
			after.SafeMode = false
		case "stopped":
			after.ServiceControl.Stopped = false
		case "revision":
			after.Revision++
		}
		data, _ := json.Marshal(after)
		if _, err := inspectFileMigrationMode(old, data, 7, true); err == nil {
			t.Fatal("offline migration changed protected intent", kind)
		}
	}
	if _, err := inspectFileMigration(old, old, 7); err == nil {
		t.Fatal("generic live migration accepted stopped configuration")
	}
}
