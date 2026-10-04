package components

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nfqwsTestCommand(t *testing.T) NFQWSSupervisionCommand {
	t.Helper()
	return NFQWSSupervisionCommand{Program: filepath.Join(t.TempDir(), "approved-nfqws"), BootID: "c257235c-b732-4f59-933e-c501adf960f5", ParentStart: "123", CommandSHA256: strings.Repeat("a", 64), ParentPID: 42, Deadline: time.Now().Add(time.Second), Args: []string{"--intercept=0"}}
}

func nfqwsTestHooks() NFQWSSupervisionHooks {
	return NFQWSSupervisionHooks{
		Armed:          func(NFQWSSupervisionIdentity) error { return nil },
		Started:        func(int) error { return nil },
		Result:         func(NFQWSSupervisionReceipt, []byte) error { return nil },
		StartAdmission: func(begin func() error) error { return begin() },
		StopCheck:      func() error { return nil },
	}
}

func TestNFQWSSupervisionCommandGate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*NFQWSSupervisionCommand, *NFQWSSupervisionHooks)
	}{
		{"missing-armed", func(_ *NFQWSSupervisionCommand, h *NFQWSSupervisionHooks) { h.Armed = nil }},
		{"missing-started", func(_ *NFQWSSupervisionCommand, h *NFQWSSupervisionHooks) { h.Started = nil }},
		{"missing-result", func(_ *NFQWSSupervisionCommand, h *NFQWSSupervisionHooks) { h.Result = nil }},
		{"missing-admission", func(_ *NFQWSSupervisionCommand, h *NFQWSSupervisionHooks) { h.StartAdmission = nil }},
		{"missing-stop", func(_ *NFQWSSupervisionCommand, h *NFQWSSupervisionHooks) { h.StopCheck = nil }},
		{"invalid-boot", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.BootID = "other" }},
		{"invalid-parent", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.ParentPID = 1 }},
		{"zero-birth", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.ParentStart = "0" }},
		{"noncanonical-birth", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.ParentStart = "0123" }},
		{"expired", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.Deadline = time.Now().Add(-time.Second) }},
		{"relative-program", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.Program = "nfqws2" }},
		{"short-hash", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.CommandSHA256 = "ab" }},
		{"uppercase-hash", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) { c.CommandSHA256 = strings.Repeat("A", 64) }},
		{"argument-nul", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) {
			c.Args = []string{"--intercept=0\x00other"}
		}},
		{"argument-size", func(c *NFQWSSupervisionCommand, _ *NFQWSSupervisionHooks) {
			c.Args = []string{strings.Repeat("x", 8193)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, hooks := nfqwsTestCommand(t), nfqwsTestHooks()
			tc.change(&command, &hooks)
			if err := validateNFQWSSupervision(context.Background(), command, hooks); !errors.Is(err, ErrNFQWSSupervisionUnknown) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if err := validateNFQWSSupervision(context.Background(), nfqwsTestCommand(t), nfqwsTestHooks()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateNFQWSSupervision(ctx, nfqwsTestCommand(t), nfqwsTestHooks()); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
