//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func (a *NFQWS2Adapter) startPreparedNFQWSProcess(request, panel context.Context, c nfqws2ActiveProcessCommand, prefix []string, admission nfqws2ActiveProcessAdmission) (prepared *NFQWSPreparedHandle, err error) {
	defer nfqws2ActivePublicError("StartPrepared", &err)
	if a == nil || panel == nil || panel.Err() != nil || !admission.valid(c) {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	activation, cancel, err := nfqws2ActiveActivationContext(request, c)
	if err != nil {
		return nil, err
	}
	identity, identityErr := admission.Provider.Observe(activation)
	if identityErr != nil || identity != c.NetworkIdentity {
		cancel()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	owner, err := a.owner()
	if err != nil || c.StateRoot != a.StateRoot || c.Owner != owner {
		cancel()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	parent, err := components.ReadNFQWSSupervisionIdentity()
	if err != nil || parent != c.Parent || nfqws2ManagedFilesCurrent(c.fileShape()) != nil || nfqws2ManagedControlCurrent(activation, c.fileShape()) != nil {
		cancel()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	program, err := os.Executable()
	if err != nil || nfqws2ManagedProtected(program, false) != nil {
		cancel()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	installed, e1 := os.Stat(program)
	running, e2 := os.Stat("/proc/self/exe")
	path := filepath.Join(a.StateRoot, nfqws2LeaseFile)
	if e1 != nil || e2 != nil || !os.SameFile(installed, running) || nfqws2ManagedProtected(path, true) != nil {
		cancel()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	root, err := os.Lstat(a.StateRoot)
	if err != nil || !root.IsDir() || root.Mode().Perm()&0o077 != 0 {
		cancel()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	c = c.clone()
	admission.Spec = admission.Spec.Clone()
	if err = admission.BeforeStart(activation, admission.Binding); err != nil {
		cancel()
		return nil, err
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		cancel()
		return nil, err
	}
	before, err := target.Read(activation)
	if err != nil || before.Exists {
		_ = target.Close()
		cancel()
		return nil, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	intent := nfqws2ActiveProcessLease{Version: 3, StateRoot: c.StateRoot, Owner: owner, Command: c, CommandSHA256: nfqws2ActiveCommandDigest(c), Binding: admission.Binding, Transfer: "none", Receipt: components.NFQWSSupervisionReceipt{State: "intent"}}
	store := nfqws2ActiveProcessStore{target: target, image: before, lease: intent}
	err = store.publish(activation)
	_ = target.Close()
	if err != nil {
		cancel()
		return nil, err
	}
	channel, endpoint, err := nfqws2ActiveSocketPair(c.ActivationDeadline)
	if err != nil {
		cancel()
		return nil, err
	} // Durable intent remains fenced.
	if prefix == nil {
		prefix = []string{"nfqws-managed-process-supervisor"}
	}
	cmd := exec.Command(program, append(slices.Clone(prefix), c.ID)...)
	cmd.Env = []string{"PATH=/opt/bin:/opt/sbin:/usr/bin:/bin", "LANG=C", "TZ=UTC", "RAZVILKA_DATAPLANE_STATE=" + filepath.Dir(filepath.Dir(a.StateRoot)), "RAZVILKA_SELF_UPDATE_CONTROL_STATE=" + c.ControlRoot}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.ExtraFiles = []*os.File{endpoint}
	done := make(chan struct{})
	identityReady := make(chan struct{})
	var settled nfqws2ActiveProcessLease
	var settleErr error
	o := &nfqws2ActiveOwner{adapter: a, command: c, admission: admission, activation: activation, panel: panel, activationCancel: cancel, transport: channel, done: done, state: "starting"}
	p := &NFQWSPreparedHandle{owner: o}
	o.prepared = p
	o.signal = func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}
	o.result = func() (nfqws2ActiveProcessLease, error) { return settled, settleErr }
	o.read = func(ctx context.Context, live bool) (nfqws2ActiveProcessLease, error) {
		return nfqws2ActiveRead(ctx, o, live)
	}
	started := false
	defer func() {
		_ = endpoint.Close()
		if err != nil {
			if started {
				o.abort()
				_, joinErr := o.join(request)
				err = errors.Join(err, joinErr)
				prepared = p
			} else {
				_ = channel.close()
				cancel()
			}
		}
	}()
	if err = a.retainNFQWSActiveProcess(o); err != nil {
		return nil, err
	}
	once := &nfqws2ActiveOnce{open: true, begin: func() error {
		startErr := admission.Provider.WithCurrent(activation, func(held context.Context, identity netidentity.Identity) error {
			if identity != c.NetworkIdentity {
				return ErrNFQWSManagedProcessUnknown
			}
			return operationgate.WithSelfUpdateEffectAdmission(held, c.ControlRoot, c.ID, c.InstallationID, c.Sequence, "nfqws-active-helper", cmd.Start)
		})
		_ = endpoint.Close()
		if cmd.Process == nil {
			return errors.Join(ErrNFQWSManagedProcessUnknown, startErr)
		}
		started = true
		go func() {
			waitErr := cmd.Wait() // The one and only parent wait owner.
			<-identityReady
			if waitErr != nil {
				settleErr = errors.Join(ErrNFQWSManagedProcessUnknown, waitErr)
			} else {
				settled, settleErr = nfqws2ActiveParentACK(o)
			}
			close(done)
		}()
		helper, readErr := components.ReadNFQWSSupervisionProcessIdentity(cmd.Process.Pid)
		base, baseErr := nfqws2ActiveFrameBase(c, admission.Binding, helper)
		o.mu.Lock()
		o.base = base
		o.mu.Unlock()
		close(identityReady)
		o.watches()
		if startErr != nil || readErr != nil || baseErr != nil {
			return errors.Join(ErrNFQWSManagedProcessUnknown, startErr, readErr, baseErr)
		}
		current := func() error {
			if err := admission.Current(activation, admission.Binding); err != nil {
				return err
			}
			actual, err := components.ReadNFQWSSupervisionProcessIdentity(helper.PID)
			if err != nil || actual != helper {
				return ErrNFQWSManagedProcessUnknown
			}
			return nfqws2ManagedControlCurrent(activation, c.fileShape())
		}
		child, err := nfqws2ActiveStartParent(activation, channel, c, base, current)
		if err != nil {
			return err
		}
		o.mu.Lock()
		o.child = child
		o.mu.Unlock()
		return nil
	}}
	err = once.invoke(func(begin func() error) error { return admission.WithStart(activation, admission.Binding, begin) })
	if err != nil {
		return nil, err
	}
	// Only positively readable empty-to-exact-owner queue transition may wait.
	for {
		ready, e := nfqwsScopedTypedQueueReadiness(activation, admission.Provider, c.NetworkIdentity, admission.Spec.Queue, &o.child)
		if e != nil {
			return nil, e
		}
		if ready {
			break
		}
		select {
		case <-activation.Done():
			return nil, activation.Err()
		case <-done:
			return nil, ErrNFQWSManagedProcessUnknown
		case <-time.After(15 * time.Millisecond):
		}
	}
	l, err := o.observe(activation, true)
	if err != nil {
		return nil, err
	}
	if err = admission.Prepared(context.WithValue(activation, nfqws2ActivePreparedKey{}, p), admission.Binding, l.observation()); err != nil {
		return nil, err
	}
	l, err = o.observe(activation, true)
	if err != nil || l.Transfer != "none" || activation.Err() != nil {
		return nil, errors.Join(ErrNFQWSManagedProcessUnknown, err, activation.Err())
	}
	o.mu.Lock()
	if o.stopRequested {
		o.mu.Unlock()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	o.state = "prepared"
	o.mu.Unlock()
	return p, nil
}

func nfqws2ActiveRead(ctx context.Context, o *nfqws2ActiveOwner, live bool) (nfqws2ActiveProcessLease, error) {
	var zero nfqws2ActiveProcessLease
	if nfqws2ActiveOperation(ctx) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	path := filepath.Join(o.command.StateRoot, nfqws2LeaseFile)
	if nfqws2ManagedProtected(path, true) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	before, err := restorejournal.ReadFileImage(ctx, path)
	l, decodeErr := nfqws2DecodeActiveLease(before, o.command.StateRoot, o.command.Owner)
	if err != nil || decodeErr != nil || !o.known(l) {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, decodeErr)
	}
	verify := func() error {
		if !live {
			return ctx.Err()
		}
		if l.Receipt.State != "running" || l.Acknowledged || nfqws2ManagedFilesCurrent(l.Command.fileShape()) != nil || nfqws2ManagedControlCurrent(ctx, l.Command.fileShape()) != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		return o.admission.Provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
			if identity != l.Command.NetworkIdentity {
				return ErrNFQWSManagedProcessUnknown
			}
			helper, e1 := components.ReadNFQWSSupervisionProcessIdentity(l.Receipt.PID)
			child, e2 := components.ReadNFQWSRuntimeProcessIdentity(l.Child.PID)
			if e1 != nil || e2 != nil || helper != o.base.Helper || child != l.Child {
				return ErrNFQWSManagedProcessUnknown
			}
			return held.Err()
		})
	}
	if err = verify(); err != nil {
		return zero, err
	}
	if live {
		if err = CheckTypedNFQWSScopedQueue(ctx, o.admission.Provider, o.command.NetworkIdentity, o.admission.Spec.Queue, &l.Child); err != nil {
			return zero, err
		}
	}
	after, err := restorejournal.ReadFileImage(ctx, path)
	if err != nil || !reflect.DeepEqual(before, after) || verify() != nil || ctx.Err() != nil {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, ctx.Err())
	}
	return l, nil
}

func nfqws2ActiveParentACK(o *nfqws2ActiveOwner) (nfqws2ActiveProcessLease, error) {
	var zero nfqws2ActiveProcessLease
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	path := filepath.Join(o.command.StateRoot, nfqws2LeaseFile)
	if nfqws2ManagedProtected(path, true) != nil {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return zero, err
	}
	defer target.Close()
	image, err := target.Read(ctx)
	l, decodeErr := nfqws2DecodeActiveLease(image, o.command.StateRoot, o.command.Owner)
	if err != nil || decodeErr != nil || l.Acknowledged || !reflect.DeepEqual(l.Command, o.command) || l.Binding != o.admission.Binding || (l.Receipt.State != "reaped" && l.Receipt.State != "not-started") {
		return zero, errors.Join(ErrNFQWSManagedProcessUnknown, err, decodeErr)
	}
	o.mu.Lock()
	if o.child == (components.NFQWSRuntimeProcessIdentity{}) {
		o.child = l.Child
	}
	o.mu.Unlock()
	if !o.known(l) {
		return zero, ErrNFQWSManagedProcessUnknown
	}
	l.Acknowledged = true
	s := nfqws2ActiveProcessStore{target: target, image: image, lease: l}
	if err = s.publish(ctx); err != nil {
		return zero, err
	}
	return l, nil
}
