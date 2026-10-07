package dataplane

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
)

type nfqws2ManagedStartDiagnosticTransport struct {
	frames  []nfqws2ManagedStartFrame
	reads   int
	sent    []nfqws2ManagedStartFrame
	readErr map[int]error
	sendErr error
	onRead  func(int)
}

func (t *nfqws2ManagedStartDiagnosticTransport) receive() (nfqws2ManagedStartFrame, error) {
	t.reads++
	if t.onRead != nil {
		t.onRead(t.reads)
	}
	if err := t.readErr[t.reads]; err != nil {
		return nfqws2ManagedStartFrame{}, err
	}
	frame := t.frames[t.reads-1]
	return frame, nil
}

func (t *nfqws2ManagedStartDiagnosticTransport) send(frame nfqws2ManagedStartFrame) error {
	t.sent = append(t.sent, frame)
	return t.sendErr
}

func (*nfqws2ManagedStartDiagnosticTransport) close() error { return nil }

func TestNFQWSManagedStartDiagnosticStagesKeepUnknownAndProtocol(t *testing.T) {
	for _, cut := range []struct {
		name, stage                  string
		reads, permits, currentCalls int
	}{
		{"ready-receive", "READY receive", 1, 0, 0},
		{"ready-frame", "READY frame", 1, 0, 0},
		{"ready-current", "READY Current", 1, 0, 1},
		{"ready-helper-read", "helper identity read", 1, 0, 1},
		{"ready-helper-changed", "helper identity changed", 1, 0, 1},
		{"ready-control", "self-update control", 1, 0, 1},
		{"ready-cancel-before", "READY context before Current", 1, 0, 0},
		{"ready-cancel-after", "READY context after Current", 1, 0, 1},
		{"permit-send", "PERMIT send", 1, 1, 1},
		{"started-receive", "STARTED receive", 2, 1, 1},
		{"started-frame", "STARTED frame", 2, 1, 1},
		{"started-child", "STARTED child identity", 2, 1, 1},
		{"started-current", "STARTED Current", 2, 1, 2},
		{"started-cancel-before", "STARTED context before Current", 2, 1, 1},
		{"started-cancel-after", "STARTED context after Current", 2, 1, 2},
		{"exact", "", 2, 1, 2},
	} {
		t.Run(cut.name, func(t *testing.T) {
			command, binding, ready, started := nfqws2ManagedStartFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := &nfqws2ManagedStartDiagnosticTransport{frames: []nfqws2ManagedStartFrame{ready, started}, readErr: map[int]error{}}
			var cause error
			switch cut.name {
			case "ready-receive":
				cause = io.EOF
				transport.readErr[1] = cause
			case "ready-frame":
				transport.frames[0].Binding.CommandSHA256 = strings.Repeat("f", 64)
			case "permit-send":
				cause = io.ErrClosedPipe
				transport.sendErr = cause
			case "started-receive":
				cause = io.EOF
				transport.readErr[2] = cause
			case "started-frame":
				transport.frames[1].Kind = "ready"
			case "started-child":
				transport.frames[1].Child.ArgumentsSHA256 = strings.Repeat("f", 64)
			case "ready-cancel-before", "started-cancel-before":
				cause = context.Canceled
				transport.onRead = func(n int) {
					if n == cut.reads {
						cancel()
					}
				}
			}
			currentCalls := 0
			current := func() error {
				currentCalls++
				switch cut.name {
				case "ready-current", "started-current":
					if currentCalls == cut.currentCalls {
						cause = ErrReviewChanged
						return nfqws2ManagedStartFailure("retained Current", cause)
					}
				case "ready-helper-read":
					cause = components.ErrNFQWSSupervisionUnknown
					return nfqws2ManagedStartFailure("helper identity read", cause)
				case "ready-helper-changed":
					return nfqws2ManagedStartFailure("helper identity changed", nil)
				case "ready-control":
					cause = ErrReviewChanged
					return nfqws2ManagedStartFailure("self-update control", cause)
				case "ready-cancel-after", "started-cancel-after":
					if currentCalls == cut.currentCalls {
						cause = context.Canceled
						cancel()
					}
				}
				return nil
			}
			err := nfqws2ManagedStartParent(ctx, transport, command, binding, ready.Helper, current)
			if transport.reads != cut.reads || len(transport.sent) != cut.permits || currentCalls != cut.currentCalls {
				t.Fatal("diagnostic changed handshake admission order", cut.name, transport.reads, transport.sent, currentCalls, err)
			}
			if cut.name == "exact" {
				if err != nil {
					t.Fatal("exact two-sided launch failed", err)
				}
				return
			}
			if !errors.Is(err, ErrNFQWSManagedProcessUnknown) || !strings.Contains(err.Error(), cut.stage) || cause != nil && !errors.Is(err, cause) {
				t.Fatal("failure lost stage/unknown/original cause", cut.name, err, cause)
			}
			for _, secret := range append([]string{command.Program.Path, command.ID, binding.CommandSHA256}, command.Args...) {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatal("diagnostic formatted command/frame metadata")
				}
			}
			// One-use lifecycle remains sealed even when the same failure is
			// returned from begin and again joined by its existing seal defer.
			calls := 0
			gate := &nfqws2ManagedStartOnce{open: true, begin: func() error { calls++; return err }}
			result := gate.invoke(func(begin func() error) error { return begin() })
			if !errors.Is(result, ErrNFQWSManagedProcessUnknown) || cause != nil && !errors.Is(result, cause) || !strings.Contains(result.Error(), cut.stage) || !errors.Is(gate.run(), ErrNFQWSManagedProcessUnknown) || calls != 1 {
				t.Fatal("failure label changed one-use outcome/replay fence", result, calls)
			}
		})
	}
}
