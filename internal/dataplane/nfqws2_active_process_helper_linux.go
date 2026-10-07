//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func runNFQWSActiveProcessSupervisor(signalCtx context.Context, id, root, control string, initial restorejournal.Image) error {
	a := NFQWS2Adapter{StateRoot: root}
	owner, err := a.owner()
	l, decodeErr := nfqws2DecodeActiveLease(initial, root, owner)
	if err != nil || decodeErr != nil || l.Command.ID != id || l.Command.ControlRoot != control || l.Receipt.State != "intent" || l.Transfer != "none" || l.Acknowledged {
		return ErrNFQWSManagedProcessUnknown
	}
	c := l.Command.clone()
	activation, cancel, err := nfqws2ActiveActivationContext(signalCtx, c)
	if err != nil {
		return err
	}
	defer cancel()
	file := os.NewFile(3, "nfqws-active-helper")
	channel, err := nfqws2ActiveSocketOpen(file, c.Parent.PID, c.ActivationDeadline)
	_ = file.Close()
	if err != nil {
		return ErrNFQWSManagedProcessUnknown
	} // No writer/Start from cold image.
	defer channel.close()
	lifetime, endLifetime := context.WithCancel(signalCtx)
	defer endLifetime()
	watchStop, watchDone := make(chan struct{}), make(chan struct{})
	var stopOnce sync.Once
	stopWatch := func() { stopOnce.Do(func() { close(watchStop) }); <-watchDone }
	defer stopWatch()
	go func() {
		defer close(watchDone)
		select {
		case <-activation.Done():
			endLifetime()
			_ = channel.close()
		case <-watchStop:
		}
	}()
	provider := netidentity.NewProcProvider()
	if c.NetworkIdentity.Kind == netidentity.ReviewedSingleInitNet {
		provider, err = netidentity.NewReviewedStockNC1812Provider(activation)
		if err != nil {
			return ErrNFQWSManagedProcessUnknown
		}
	}
	path := filepath.Join(root, nfqws2LeaseFile)
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return err
	}
	defer target.Close()
	image, err := target.Read(activation)
	actual, decodeErr := nfqws2DecodeActiveLease(image, root, owner)
	if err != nil || decodeErr != nil || !reflect.DeepEqual(initial, image) || !reflect.DeepEqual(actual, l) {
		return ErrNFQWSManagedProcessUnknown
	}
	store := nfqws2ActiveProcessStore{target: target, image: image, lease: l}
	var protocol *nfqws2ActiveHelperProtocol
	current := func() error {
		if activation.Err() != nil || nfqws2ManagedFilesCurrent(c.fileShape()) != nil || nfqws2ManagedControlCurrent(activation, c.fileShape()) != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		parent, err := components.ReadNFQWSSupervisionProcessIdentity(c.Parent.PID)
		if err != nil || parent != c.Parent || os.Getppid() != c.Parent.PID {
			return ErrNFQWSManagedProcessUnknown
		}
		if store.lease.Receipt.Started {
			child, err := components.ReadNFQWSRuntimeProcessIdentity(store.lease.Child.PID)
			if err != nil || child != store.lease.Child {
				return ErrNFQWSManagedProcessUnknown
			}
		}
		identity, err := provider.Observe(activation)
		if err != nil || identity != c.NetworkIdentity {
			return ErrNFQWSManagedProcessUnknown
		}
		return activation.Err()
	}
	if err = current(); err != nil {
		return err
	}
	terminal := false
	hooks := components.NFQWSSupervisionHooks{
		Armed: func(helper components.NFQWSSupervisionIdentity) error {
			store.lease.Receipt = components.NFQWSSupervisionReceipt{State: "armed", BootID: helper.BootID, Start: helper.Start, PID: helper.PID, Group: helper.Group, CommandSHA256: store.lease.CommandSHA256}
			if err := store.publish(activation); err != nil {
				return err
			}
			base, err := nfqws2ActiveFrameBase(c, store.lease.Binding, helper)
			if err != nil {
				return err
			}
			protocol = &nfqws2ActiveHelperProtocol{transport: channel, command: c, base: base}
			return protocol.ready()
		},
		StartAdmission: func(begin func() error) error {
			return protocol.admit(activation, current, func() error {
				return provider.WithCurrent(activation, func(held context.Context, identity netidentity.Identity) error {
					if identity != c.NetworkIdentity {
						return ErrNFQWSManagedProcessUnknown
					}
					return operationgate.WithSelfUpdateEffectAdmission(held, control, id, c.InstallationID, c.Sequence, "nfqws-active-child", begin)
				})
			})
		},
		Started: func(pid int) error {
			child, err := components.ReadNFQWSRuntimeProcessIdentity(pid)
			if err != nil {
				return err
			}
			store.lease.Receipt.State, store.lease.Receipt.Started, store.lease.Receipt.ChildPID = "running", true, pid
			store.lease.Child = child
			if err = store.publish(activation); err != nil {
				return err
			}
			if err = protocol.started(child); err != nil {
				return err
			}
			if err = protocol.transfer(activation, current, func(phase string) error {
				store.lease.Transfer = phase
				return store.publish(activation)
			}); err != nil {
				return err
			}
			stopWatch() // Join the activation timer before long-lived wait begins.
			if activation.Err() != nil || lifetime.Err() != nil {
				return ErrNFQWSManagedProcessUnknown
			}
			_ = channel.close()
			return nil
		},
		StopCheck: func() error {
			fresh, finish := context.WithTimeout(lifetime, 2*time.Second)
			defer finish()
			return nfqws2ManagedControlCurrent(fresh, c.fileShape())
		},
		Result: func(receipt components.NFQWSSupervisionReceipt, _ []byte) error {
			armed := store.lease.Receipt
			if receipt.PID != armed.PID || receipt.Group != armed.Group || receipt.Start != armed.Start || receipt.BootID != c.NetworkIdentity.BootID || receipt.CommandSHA256 != store.lease.CommandSHA256 {
				return ErrNFQWSManagedProcessUnknown
			}
			store.lease.Receipt = receipt
			cleanup, finish := context.WithTimeout(context.Background(), 2*time.Second)
			defer finish()
			if err := store.publish(cleanup); err != nil {
				return err
			}
			terminal = true
			return nil
		},
	}
	receipt, runErr := components.RunNFQWSActiveSupervision(lifetime, components.NFQWSActiveSupervisionCommand{Program: c.Program.Path, Args: slices.Clone(c.Args), BootID: c.NetworkIdentity.BootID, ParentPID: c.Parent.PID, ParentStart: c.Parent.Start, CommandSHA256: store.lease.CommandSHA256}, hooks)
	if !terminal || !receipt.WaitECHILD || (runErr != nil && receipt.ExitCode == 0 && !receipt.Cancelled) {
		return errors.Join(ErrNFQWSManagedProcessUnknown, runErr)
	}
	return nil
}
