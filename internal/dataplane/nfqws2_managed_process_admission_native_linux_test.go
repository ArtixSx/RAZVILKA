//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func nfqws2ManagedNativeBinding(command nfqws2ManagedProcessCommand) nfqws2ManagedStartBinding {
	return nfqws2ManagedStartBinding{ExecutionID: "dp-check-" + strings.Repeat("1", 32), PlanID: "dp-0123456789abcdef", PlanDigest: strings.Repeat("2", 64), ResourceID: "nq-" + strings.Repeat("3", 32), ResourceGeneration: strings.Repeat("4", 64), EffectsDigest: strings.Repeat("5", 64), SessionID: command.ID, CommandSHA256: nfqws2ManagedCommandDigest(command)}
}

// ROOT-only actual Start/receipt/channel proof. This does not impersonate a
// production Manager or prove LAN/queue/capture scope admission.
func TestNFQWSManagedProcessLaunchBridgeNative(t *testing.T) {
	program := nfqws2ManagedNativeGate(t)
	prefix := []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"}
	for n, mode := range []string{"exact", "pending-denied", "scope-closed", "prepared-denied", "scoped-intent-without-channel", "current-denied-after-ready", "panic-before-start", "panic-after-start", "panic-current", "panic-prepared"} {
		t.Run(mode, func(t *testing.T) {
			daemonMode := "normal"
			if mode == "prepared-denied" || mode == "panic-after-start" || mode == "panic-prepared" {
				daemonMode = "hold"
			}
			a, command := nfqws2ManagedNativePrepare(t, program, fmt.Sprintf("%032x", n+100), daemonMode)
			binding := nfqws2ManagedNativeBinding(command)
			if mode == "scoped-intent-without-channel" {
				path := filepath.Join(a.StateRoot, nfqws2LeaseFile)
				target, err := restorejournal.OpenFileTarget(path)
				if err != nil {
					t.Fatal(err)
				}
				image, err := target.Read(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				store := nfqws2ManagedProcessStore{target: target, image: image, lease: nfqws2ManagedProcessLease{Version: 2, StateRoot: a.StateRoot, Owner: command.Owner, Command: command, CommandSHA256: binding.CommandSHA256, LaunchBinding: &binding, Receipt: components.NFQWSSupervisionReceipt{State: "intent"}}}
				if err := store.publish(context.Background()); err != nil {
					t.Fatal(err)
				}
				store.close()
				before, err := restorejournal.ReadFileImage(context.Background(), path)
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(program, append(prefix, command.ID)...)
				cmd.Env = []string{"PATH=/usr/bin:/bin", "RAZVILKA_DATAPLANE_STATE=" + filepath.Dir(filepath.Dir(a.StateRoot)), "RAZVILKA_SELF_UPDATE_CONTROL_STATE=" + command.ControlRoot}
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				if err := cmd.Run(); err == nil {
					t.Fatal("persisted scoped intent alone granted child Start")
				}
				after, err := restorejournal.ReadFileImage(context.Background(), path)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("missing channel changed process intent", err)
				}
				return
			}
			pending, inBarrier, prepared := false, false, false
			var retained func() error
			var panicAt time.Time
			hooks := nfqws2ManagedProcessAdmission{Binding: binding,
				Current: func(ctx context.Context, got nfqws2ManagedStartBinding) error {
					if !pending || !inBarrier || got != binding {
						t.Fatal("late current outside retained barrier")
					}
					if mode == "current-denied-after-ready" {
						return ErrNFQWSScopedOwner
					}
					if mode == "panic-current" {
						panicAt = time.Now()
						panic("current fixture")
					}
					return ctx.Err()
				},
				BeforeStart: func(ctx context.Context, got nfqws2ManagedStartBinding) error {
					if got != binding {
						t.Fatal("pending used different binding")
					}
					if _, err := os.Lstat(filepath.Join(a.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("intent existed before pending", err)
					}
					if mode == "pending-denied" {
						return ErrNFQWSScopedOwner
					}
					pending = true
					return nil
				},
				WithStart: func(ctx context.Context, got nfqws2ManagedStartBinding, begin func() error) error {
					if !pending || got != binding {
						t.Fatal("Start before pending")
					}
					retained = begin
					if mode == "panic-before-start" {
						panicAt = time.Now()
						panic("scope fixture")
					}
					if mode == "scope-closed" {
						return ErrNFQWSScopedOwner
					}
					inBarrier = true
					defer func() { inBarrier = false }()
					if err := begin(); err != nil {
						return err
					}
					if mode == "panic-after-start" {
						panicAt = time.Now()
						panic("scope fixture")
					}
					lease, err := a.observeManagedNFQWSProcessRunning(ctx)
					if err != nil || lease.LaunchBinding == nil || *lease.LaunchBinding != binding {
						t.Fatal("barrier released before actual durable Start ACK", err)
					}
					return nil
				},
				Prepared: func(ctx context.Context, got nfqws2ManagedStartBinding) error {
					if inBarrier || !pending || got != binding {
						t.Fatal("prepared ran inside barrier or lost pending")
					}
					if _, err := a.observeManagedNFQWSProcessRunning(ctx); err != nil {
						t.Fatal("prepared without actual child", err)
					}
					prepared = true
					if mode == "panic-prepared" {
						panicAt = time.Now()
						panic("prepared fixture")
					}
					if mode == "prepared-denied" {
						return ErrNFQWSScopedOwner
					}
					return nil
				},
			}
			var lease nfqws2ManagedProcessLease
			var err error
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				lease, err = a.runManagedNFQWSProcessWithAdmission(context.Background(), command, prefix, hooks)
			}()
			if strings.HasPrefix(mode, "panic-") {
				if !panicked || prepared != (mode == "panic-prepared") || retained == nil || !errors.Is(retained(), ErrNFQWSManagedProcessUnknown) {
					t.Fatal("exceptional return left Start borrower live")
				}
				got, _ := nfqws2ManagedNativeRead(t, a)
				if got.Acknowledged {
					t.Fatal("panic fabricated parent terminal ACK")
				}
				if mode == "panic-before-start" {
					if got.Receipt.State != "intent" || got.Receipt.PID != 0 {
						t.Fatal("late callback launched helper after panic", got.Receipt)
					}
				} else if mode == "panic-current" {
					if time.Since(panicAt) > nfqws2ManagedJoinGrace+500*time.Millisecond || !got.Receipt.WaitECHILD || got.Receipt.Started || got.Receipt.DirectReaped {
						t.Fatal("Current panic started child or escaped bounded cleanup", got.Receipt)
					}
				} else {
					if time.Since(panicAt) > nfqws2ManagedJoinGrace+500*time.Millisecond || !got.Receipt.WaitECHILD || !got.Receipt.DirectReaped || !got.Receipt.Cancelled {
						t.Fatal("panic did not bound exact helper cleanup", got.Receipt)
					}
					if _, err := a.observeManagedNFQWSProcessInactive(context.Background()); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
						t.Fatal("unacknowledged panic became inactive proof", err)
					}
				}
				return
			}
			if panicked {
				t.Fatal("unexpected producer panic")
			}
			if mode == "exact" {
				if err != nil || !pending || !prepared || !nfqws2ManagedProcessSettled(lease) {
					t.Fatal("exact channel Start/terminal failed", err, lease.Receipt)
				}
			} else if err == nil {
				t.Fatal("denied phase admitted successful launch")
			}
			if mode == "prepared-denied" && (!lease.Acknowledged || !lease.Receipt.WaitECHILD || !lease.Receipt.Cancelled) {
				t.Fatal("prepared refusal lost independent terminal receipt", lease.Receipt)
			}
			if retained != nil && !errors.Is(retained(), ErrNFQWSManagedProcessUnknown) {
				t.Fatal("retained Start callback replayed")
			}
			if mode == "pending-denied" {
				if _, err := os.Lstat(filepath.Join(a.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("denied pending wrote intent", err)
				}
			}
			if mode == "scope-closed" {
				got, _ := nfqws2ManagedNativeRead(t, a)
				if got.Receipt.State != "intent" || got.Receipt.PID != 0 || got.Acknowledged {
					t.Fatal("scope closure fabricated process result", got.Receipt)
				}
			}
		})
	}
}
