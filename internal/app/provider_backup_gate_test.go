package app

import (
	"testing"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

func TestLegacyRestoreCannotSilentlyDropProviderSnapshots(t *testing.T) {
	a := &App{}
	payload := privatebackup.NewPayload("0.18.1-dev")
	payload.ProviderSnapshots = []privatebackup.ProviderSnapshot{{Provider: "cloudflare"}}
	if _, err := a.previewPrivateBackup(payload); err == nil {
		t.Fatal("unsupported provider restore reported success")
	}
}

func TestLegacyRestoreCannotSilentlyDropNodeSnapshot(t *testing.T) {
	a := &App{}
	payload := privatebackup.NewPayload("0.18.1-dev")
	payload.NodeSnapshot = &nodestore.PrivateSnapshot{}
	if _, err := a.previewPrivateBackup(payload); err == nil {
		t.Fatal("unsupported node restore reported success")
	}
}
