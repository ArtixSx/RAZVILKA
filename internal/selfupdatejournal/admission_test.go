package selfupdatejournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicFileEffectRequiresFreshLinearizedAdmission(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	ctx := context.Background()
	stopped := errors.New("durable Stop accepted before rename")
	starts := 0
	admit := func(c context.Context, effect string, begin func() error) error {
		if effect != "install-file-0" {
			t.Fatal("unexpected effect")
		}
		// Model the Stop barrier after readonly authority/quiescence checks
		// and before the actual filesystem syscall under the control lock.
		starts++
		return stopped
	}
	if !errors.Is(f.store.InstallAdmitted(ctx, transaction, okay, okay, admit), stopped) || starts != 1 {
		t.Fatal("Stop/start barrier was bypassed")
	}
	f.old(t)
	if err := f.store.InstallAdmitted(ctx, transaction, okay, okay, func(c context.Context, effect string, begin func() error) error { return begin() }); err != nil {
		t.Fatal("known file CAS cannot continue after renewed matching admission", err)
	}
	if err := f.store.RestoreAdmitted(ctx, transaction, okay, okay, nil); !errors.Is(err, ErrMismatch) {
		t.Fatal("missing admission accepted")
	}
}

func TestTerminalArtifactsPermitLaterConfigButKeepReleaseIntegrity(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	f.install(t)
	ctx := context.Background()
	if f.store.VerifyTerminalArtifacts(ctx, transaction, false) == nil {
		t.Fatal("pending installation mistaken for terminal")
	}
	if err := f.store.Accept(ctx, transaction, false, okay, okay); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.installation, "etc/razvilka/config.json")
	if err := os.WriteFile(path, []byte("legitimate later configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if f.store.VerifyInstallation(ctx, transaction, false) == nil {
		t.Fatal("strict pending image verification weakened")
	}
	if err := f.store.VerifyTerminalArtifacts(ctx, transaction, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.installation, "bin/razvilka"), []byte("foreign binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if f.store.VerifyTerminalArtifacts(ctx, transaction, false) == nil {
		t.Fatal("foreign executable accepted")
	}
}
