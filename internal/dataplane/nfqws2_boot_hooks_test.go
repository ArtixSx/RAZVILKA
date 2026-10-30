package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNFQWS2BootHooksLossUsesWALBeforeEffectsAndKeepsSameRuntime(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h := newNFQWS2HookFixture(t, false)
	plan := h.committed(t)
	files := h.files(t)
	identity := h.identity
	h.lose(t, 4)
	allow := true
	calls := len(h.calls)
	h.beforeWrite = func(_ int, _ int, _ []string) error {
		raw, err := os.ReadFile(filepath.Join(h.m.StateRoot, nfqws2BootHookJournal))
		if err != nil {
			return err
		}
		if !strings.Contains(string(raw), `"State":"pending"`) && !strings.Contains(string(raw), `"state":"pending"`) {
			return errors.New("effect has no durable pending record")
		}
		return nil
	}
	recovery, err := h.m.Recover(h.bootContext(t, &allow))
	if err != nil || recovery.State != "recovered" {
		t.Fatal(recovery, err)
	}
	if len(h.writes) == 0 || h.identity != identity || !h.running {
		t.Fatal("repair did not preserve exact live runtime")
	}
	for _, call := range h.calls[calls:] {
		if firstStartRuntimeAction(call) {
			t.Fatal("healthy boot repair changed runtime", call)
		}
	}
	h.assertFiles(t, files)
	if err := h.a.Health(firstStartContext(t), plan, ""); err != nil {
		t.Fatal(err)
	}
	if err := h.m.checkNFQWS2BootHookJournal(); err != nil {
		raw, _ := os.ReadFile(filepath.Join(h.m.StateRoot, nfqws2BootHookJournal))
		t.Fatal("acknowledged repair not terminal", err, string(raw))
	}
	raw, _ := os.ReadFile(filepath.Join(h.m.StateRoot, nfqws2BootHookJournal))
	writes := len(h.writes)
	if _, err := h.m.Recover(h.bootContext(t, &allow)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(h.m.StateRoot, nfqws2BootHookJournal))
	if string(raw) != string(after) || len(h.writes) != writes {
		t.Fatal("FULL rewrote WAL or kernel")
	}
}

func TestNFQWS2BootHooksFullReadOnlyAndLossWithoutReviewRefused(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"full", "loss-no-review", "partial"} {
		t.Run(which, func(t *testing.T) {
			h := newNFQWS2HookFixture(t, false)
			allow := true
			ctx := h.bootContext(t, &allow)
			if which == "loss-no-review" {
				h.lose(t, 4)
				ctx = firstStartContext(t)
			}
			if which == "partial" {
				h.kernel.families[4]["mangle"].rules["nfqws_post"] = nil
			}
			_, err := h.m.Recover(ctx)
			if (which == "full") != (err == nil) {
				t.Fatal(which, err)
			}
			if len(h.writes) != 0 {
				t.Fatal("unadmitted kernel effects")
			}
			if _, err := os.Stat(filepath.Join(h.m.StateRoot, nfqws2BootHookJournal)); !os.IsNotExist(err) {
				t.Fatal("FULL/refused branch wrote WAL", err)
			}
		})
	}
}

func TestNFQWS2BootHooksInterruptedEffectFencesNextRecovery(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h := newNFQWS2HookFixture(t, false)
	h.lose(t, 4)
	allow := true
	h.beforeWrite = func(_ int, _ int, _ []string) error { return context.Canceled }
	if _, err := h.m.Recover(h.bootContext(t, &allow)); err == nil {
		t.Fatal("failed native effect accepted")
	}
	raw, err := os.ReadFile(filepath.Join(h.m.StateRoot, nfqws2BootHookJournal))
	if err != nil {
		t.Fatal(err)
	}
	// Even a complete external-looking graph must not make uncertain effects safe.
	h.kernel = h.fullKernel(t)
	writes := len(h.writes)
	calls := len(h.calls)
	recovery, err := h.m.Recover(h.bootContext(t, &allow))
	if !errors.Is(err, ErrExecutionJournal) || recovery.State != "journal-recovery-required" {
		t.Fatal(recovery, err)
	}
	if len(h.writes) != writes || len(h.calls) != calls {
		t.Fatal("fenced boot reached native commands")
	}
	after, _ := os.ReadFile(filepath.Join(h.m.StateRoot, nfqws2BootHookJournal))
	if string(raw) != string(after) {
		t.Fatal("uncertain original evidence changed")
	}
}

func TestNFQWS2BootHooksRevokedIntentNeverWrites(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h := newNFQWS2HookFixture(t, false)
	h.lose(t, 4)
	allow := false
	if _, err := h.m.Recover(h.bootContext(t, &allow)); err == nil {
		t.Fatal("revoked intent admitted")
	}
	if len(h.writes) != 0 {
		t.Fatal("revoked authority changed kernel")
	}
}

func TestNFQWS2BootHooksUnknownTerminalVocabularyFences(t *testing.T) {
	for _, c := range []NFQWS2HookCommand{{Family: 4, Args: []string{"-F"}}, {Family: 4, Args: []string{"-t", "mangle", "-A", "POSTROUTING", "-j", "ACCEPT"}}, {Family: 6, Args: []string{"-t", "nat", "-N", "nfqws_nat"}}} {
		if validNFQWS2BootHookCommand(c) {
			t.Fatal("unknown acknowledged command accepted", c)
		}
	}
	if validNFQWS2BootHookInstance("anything") {
		t.Fatal("unknown instance accepted")
	}
}

func TestNFQWS2BootHooksMidWriteFailureRollsBackOnlyAttempt(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h := newNFQWS2HookFixture(t, false)
	h.lose(t, 4)
	loss := h.kernel.rows()
	// Manager.Recover deliberately deactivates after a failed reconciliation.
	// Inspect the rollback before that independent safety operation changes it.
	stopped := false
	inner := h.a.Runner
	h.a.Runner = nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == h.a.InitPath && len(args) == 1 && args[0] == "owned_stop" {
			stopped = true
			if len(h.writes) <= 5 || !slices.EqualFunc(h.kernel.rows(), loss, nfqws2HookSameRow) {
				t.Fatal("rollback left residue or changed foreign objects before safety stop", h.kernel.save(4))
			}
		}
		return inner.Run(ctx, name, args...)
	})
	allow := true
	h.beforeWrite = func(n int, _ int, _ []string) error {
		if n == 5 {
			return errors.New("injected fifth write failure")
		}
		return nil
	}
	if _, err := h.m.Recover(h.bootContext(t, &allow)); err == nil {
		t.Fatal("failed restoration accepted")
	}
	if !stopped || h.running {
		t.Fatal("failed boot repair did not deactivate owned runtime")
	}
	if err := h.m.CheckNFQWS2BootHookRecovery(); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("failed effect lost its recovery fence", err)
	}
}

func TestNFQWS2BootHooksReplacedJournalIsNotOverwritten(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h := newNFQWS2HookFixture(t, false)
	h.lose(t, 4)
	allow := true
	path := filepath.Join(h.m.StateRoot, nfqws2BootHookJournal)
	replacement := []byte(`{"state":"external-pending-evidence"}`)
	h.beforeWrite = func(n int, _ int, _ []string) error {
		if n == 1 {
			return os.WriteFile(path, replacement, 0600)
		}
		return nil
	}
	if _, err := h.m.Recover(h.bootContext(t, &allow)); err == nil {
		t.Fatal("replaced journal accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(replacement) {
		t.Fatal("replacement evidence overwritten", err)
	}
	if err := h.m.CheckNFQWS2BootHookRecovery(); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("replacement journal did not fence recovery", err)
	}
}
