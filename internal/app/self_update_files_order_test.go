package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func assertFileUpdateImages(t *testing.T, a *App, p *fileUpdateProof, old bool) {
	t.Helper()
	for _, file := range p.files {
		actual, err := os.ReadFile(filepath.Join(a.SelfUpdateFiles.Installation, file.Target))
		if err != nil {
			t.Fatal(err)
		}
		want := "reviewed-new-" + file.Target
		if old {
			want = "old-" + file.Target
		}
		if string(actual) != want {
			t.Fatal("unexpected replacement order", file.Target, old)
		}
	}
}

func TestSelfUpdateFilesAdmittedPreFileOrderAndRollback(t *testing.T) {
	a, p := fileUpdateHTTPFixture(t)
	if err := fileUpdateAction(t, a, "prepare"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"install", "start-candidate-panel", "prepare-private-state", "quiesce-old-runtime", "restore-private-state", "start-rollback-panel"} {
		if !errors.Is(fileUpdateAction(t, a, action), selfupdatejournal.ErrPending) {
			t.Fatal("out-of-order effect admitted", action)
		}
	}
	assertFileUpdateImages(t, a, p, true)
	if len(p.runs) != 0 || len(p.effects) != 0 {
		t.Fatal("rejected order reached effect callbacks", p.runs, p.effects)
	}
	p.runHook = func(command string) error {
		switch command {
		case "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "restore-private-state", "start-rollback-panel":
			assertFileUpdateImages(t, a, p, true)
		case "start-candidate-panel", "stop-candidate-panel":
			assertFileUpdateImages(t, a, p, false)
		default:
			t.Fatal("unknown command", command)
		}
		return nil
	}
	if err := fileUpdateAction(t, a, "stop-old-panel"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(fileUpdateAction(t, a, "install"), selfupdatejournal.ErrPending) || !errors.Is(fileUpdateAction(t, a, "quiesce-old-runtime"), selfupdatejournal.ErrPending) {
		t.Fatal("stop alone granted replacement or skipped private preparation")
	}
	for _, action := range []string{"prepare-private-state", "quiesce-old-runtime"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	p.effectError = errors.New("effect admission revoked before rename")
	if !errors.Is(fileUpdateAction(t, a, "install"), p.effectError) {
		t.Fatal("replacement skipped admitted effect callback")
	}
	assertFileUpdateImages(t, a, p, true)
	r, present, err := a.SelfUpdateFiles.Current()
	if err != nil || !present || r.Phase != "installing" || r.Index != 0 {
		t.Fatal("unadmitted rename advanced the journal", r, err)
	}
	p.effectError = nil
	if err := fileUpdateAction(t, a, "install"); err != nil {
		t.Fatal("known file checkpoint could not resume", err)
	}
	assertFileUpdateImages(t, a, p, false)
	for _, action := range []string{"start-candidate-panel", "stop-candidate-panel", "restore"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	assertFileUpdateImages(t, a, p, true)
	if !errors.Is(fileUpdateAction(t, a, "start-rollback-panel"), selfupdatejournal.ErrPending) {
		t.Fatal("rollback panel started before private state restoration")
	}
	for _, action := range []string{"restore-private-state", "start-rollback-panel", "accept-rollback"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	want := []string{"start/live:install-file-0"} // First admission refused, no rename.
	for i := 0; i < 6; i++ {
		want = append(want, fmt.Sprintf("start/live:install-file-%d", i))
	}
	for i := 0; i < 6; i++ {
		want = append(want, fmt.Sprintf("replace-to-rollback:rollback-file-%d", i))
	}
	if !reflect.DeepEqual(p.effects, want) {
		t.Fatal("wrong file effect identity or action authority", p.effects)
	}
}

func TestSelfUpdateFilesUnknownPreFileCommandCannotReplaceOrReplay(t *testing.T) {
	a, p := fileUpdateHTTPFixture(t)
	p.runHook = func(command string) error {
		if command == "quiesce-old-runtime" {
			return errors.New("supervised runtime outcome unknown")
		}
		return nil
	}
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(err)
		}
	}
	if err := fileUpdateAction(t, a, "quiesce-old-runtime"); err == nil {
		t.Fatal("unknown command reported successful")
	}
	for _, action := range []string{"quiesce-old-runtime", "install", "restore", "start-candidate-panel"} {
		if err := fileUpdateAction(t, a, action); err == nil {
			t.Fatal("unknown outcome granted effect/replay", action)
		}
	}
	assertFileUpdateImages(t, a, p, true)
	if len(p.runs) != 3 || len(p.effects) != 0 {
		t.Fatal("unknown pre-file command replayed or replaced files", p.runs, p.effects)
	}
	r, _, err := a.SelfUpdateFiles.Current()
	if err != nil || r.Phase != "command-started" || r.Command != "quiesce-old-runtime" || !r.BeforeFiles {
		t.Fatal("unknown receipt was settled without observation", r, err)
	}
	// Observe may settle known completion; it does not rerun the command.
	if err := a.SelfUpdateFiles.Action(context.Background(), fileUpdateID, "resolve-unknown", p.revision, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(p.runs) != 3 {
		t.Fatal("observation replayed the external command")
	}
}
