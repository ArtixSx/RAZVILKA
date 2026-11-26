package privaterestore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func policyRestoreFixture(t *testing.T, s *config.Store) (privatebackup.Payload, config.Config) {
	t.Helper()
	local := config.DefaultServicePolicy("youtube", s.Get().AppliedServices["youtube"])
	local.Enabled, local.Mode, local.TrustClasses = true, "auto", []string{"manual"}
	if _, err := s.UpdateServicePolicy(local, s.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	payload := testPayload(t)
	imported := config.DefaultServicePolicy("custom-import", config.ServiceState{Sources: []string{"192.168.1.40/32"}})
	imported.Revision, imported.Enabled, imported.Mode, imported.LegacyOptIn = 7, true, "auto", true
	imported.AllowedNodeIDs = []string{"node-" + strings.Repeat("a", 64)}
	imported.AllowedSourceIDs = []string{"feed-kort0881-ru-sni"}
	imported.TrustClasses = []string{"community"}
	imported.PinFallback = true
	conflicting := imported
	conflicting.ServiceID = "youtube"
	payload.ServicePolicies = map[string]config.ServicePolicy{"youtube": conflicting, "custom-import": imported}
	if err := privatebackup.Seal(&payload); err != nil {
		t.Fatal(err)
	}
	return payload, before
}

func requireRestoredPolicyBoundaries(t *testing.T, before, after config.Config, payload privatebackup.Payload) {
	t.Helper()
	if !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) || before.SafeMode != after.SafeMode || before.AppliedRevision != after.AppliedRevision || !reflect.DeepEqual(before.ServicePolicies["youtube"], after.ServicePolicies["youtube"]) {
		t.Fatal("restore changed current working route or existing local automatic authority")
	}
	want, err := config.NormalizeServicePolicy(payload.ServicePolicies["custom-import"])
	if err != nil {
		t.Fatal(err)
	}
	want.Enabled, want.Mode, want.Revision, want.LegacyOptIn = false, "paused", 1, false
	if !reflect.DeepEqual(after.ServicePolicies["custom-import"], want) || after.Revision != before.Revision+1 {
		t.Fatal("new policy was not restored paused with exact saved restrictions")
	}
}

func TestPolicyRestoreUsesExistingJournalOnlineAndSurvivesRestartPaused(t *testing.T) {
	c, layout, stores := onlineFixture(t)
	payload, before := policyRestoreFixture(t, stores.Config)
	envelope, err := privatebackup.Encrypt(payload, "policy-restore-password")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := privatebackup.Decrypt(envelope, "policy-restore-password")
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.RestoreOnline(context.Background(), decrypted, map[string]bool{"youtube": true}, stores)
	if err != nil || out != restorejournal.Applied {
		t.Fatal(out, err)
	}
	requireLiveCaches(t, layout, stores)
	requireRestoredPolicyBoundaries(t, before, stores.Config.Get(), payload)
	if journalState(t, layout) != "idle" {
		t.Fatal("policy restore left a pending journal")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, out, err := Open(context.Background(), layout)
	if err != nil || out != restorejournal.Clean {
		t.Fatal(out, err)
	}
	defer reopened.Close()
	loaded, err := config.Load(layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	requireRestoredPolicyBoundaries(t, before, loaded.Get(), payload)
}

func TestPolicyRestoreOfflinePreservesExistingAuthorityAndRejectsUnknownServices(t *testing.T) {
	layout := seedLayout(t, t.TempDir())
	store, err := config.Load(layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	payload, before := policyRestoreFixture(t, store)
	c, _, err := Open(context.Background(), layout)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	beforeImages := imagesOnDisk(t, layout)
	unknown := payload.ServicePolicies["custom-import"]
	unknown.ServiceID = "unknown-policy-service"
	payload.ServicePolicies[unknown.ServiceID] = unknown
	if err := privatebackup.Seal(&payload); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RestoreOffline(context.Background(), payload, map[string]bool{"youtube": true}); !errors.Is(err, restorejournal.ErrInvalid) {
		t.Fatal("unknown policy service accepted")
	}
	requireImages(t, layout, beforeImages)
	delete(payload.ServicePolicies, unknown.ServiceID)
	if err := privatebackup.Seal(&payload); err != nil {
		t.Fatal(err)
	}
	out, err := c.RestoreOffline(context.Background(), payload, map[string]bool{"youtube": true})
	if err != nil || out != restorejournal.Applied {
		t.Fatal(out, err)
	}
	loaded, err := config.Load(layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	requireRestoredPolicyBoundaries(t, before, loaded.Get(), payload)
}

func TestPolicyRestoreFailureRollsBackPolicyAndDraftTogether(t *testing.T) {
	c, layout, stores := onlineFixture(t)
	payload, before := policyRestoreFixture(t, stores.Config)
	beforeImages := imagesOnDisk(t, layout)
	c.beforeWrite = func(id string) error {
		if id == "devices" {
			return errors.New("stop after config policy write")
		}
		return nil
	}
	out, err := c.RestoreOnline(context.Background(), payload, map[string]bool{"youtube": true}, stores)
	if err == nil || out != restorejournal.RolledBack {
		t.Fatal("injected policy restore error did not roll back", out, err)
	}
	if !reflect.DeepEqual(before, stores.Config.Get()) {
		t.Fatal("failed archive changed policy authority or draft")
	}
	requireImages(t, layout, beforeImages)
	requireLiveCaches(t, layout, stores)
}
