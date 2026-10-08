//go:build linux

package nativeowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

type ownedMetadata struct {
	name string
	info os.FileInfo
	hash string
}
type linuxSession struct {
	facts                                              *linuxFacts
	offer                                              offer
	root                                               *os.Root
	rootInfo                                           os.FileInfo
	binary, config                                     *heldFile
	control                                            *controlAnchors
	gate                                               chan struct{}
	cmd                                                *exec.Cmd
	channel                                            *channel
	helper                                             components.NFQWSSupervisionIdentity
	child                                              components.NFQWSRuntimeProcessIdentity
	passport                                           routeidentity.Passport
	metadata                                           []ownedMetadata
	waitOnce                                           sync.Once
	done                                               chan struct{}
	waitErr                                            error // written before closing done, read only after done
	offerSent, started, acknowledged, joined, released bool
	terminal                                           components.NFQWSSupervisionReceipt
}

func (r *linuxSession) lock(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrOwned
	}
	select {
	case <-ctx.Done():
		return ErrOwned
	case <-r.gate:
		return nil
	}
}
func (r *linuxSession) unlock() { r.gate <- struct{}{} }

func (r *linuxSession) assetsCurrent(ctx context.Context) error {
	if ctx.Err() != nil || r.root == nil || r.rootInfo == nil || r.binary.current(ctx) != nil || r.config.current(ctx) != nil || r.control.current() != nil {
		return ErrOwned
	}
	actual, e1 := os.Lstat(r.offer.Launch.Process.Dir)
	anchored, e2 := r.root.Stat(".")
	if e1 != nil || e2 != nil || actual.Mode()&os.ModeSymlink != 0 || actual.Mode().Perm()&0o077 != 0 || !os.SameFile(actual, r.rootInfo) || !os.SameFile(anchored, r.rootInfo) {
		return ErrOwned
	}
	return nil
}

func (r *linuxSession) armWait() {
	if r.cmd == nil || r.cmd.Process == nil {
		return
	}
	r.waitOnce.Do(func() { r.done = make(chan struct{}); go func() { r.waitErr = r.cmd.Wait(); close(r.done) }() })
}

func (r *linuxSession) Start(ctx context.Context, original OriginalLease) (err error) {
	if r.lock(ctx) != nil {
		return ErrOwned
	}
	defer r.unlock()
	if r.cmd != nil || r.released || r.assetsCurrent(ctx) != nil {
		return ErrOwned
	}
	deadline, _ := ctx.Deadline()
	ch, endpoint, err := channelPair(deadline)
	if err != nil {
		return ErrOwned
	}
	r.channel = ch
	defer endpoint.Close()
	endIO, err := ch.withContext(ctx)
	if err != nil {
		return ErrOwned
	}
	defer endIO()
	dir, err := r.root.Open(".")
	if err != nil {
		return ErrOwned
	}
	defer dir.Close()
	// Descriptor execution pins the reviewed helper inode. IPC/config/binary/
	// directory/namespace descriptors are inherited privately, never CLI grants.
	r.cmd = exec.Command("/proc/self/fd/4")
	r.cmd.Args = []string{r.facts.scope.Helper.Path}
	r.cmd.Env = []string{"LANG=C"}
	r.cmd.ExtraFiles = []*os.File{endpoint, r.facts.helper.file, r.config.file, r.binary.file, dir, r.facts.namespace, r.control.directory, r.control.lock}
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	defer r.armWait() // including an original admission panic after actual Start
	actual := startOnce{open: true, begin: func() error {
		if r.facts.helper.metadataCurrent(ctx) != nil || r.binary.metadataCurrent(ctx) != nil || r.config.metadataCurrent(ctx) != nil {
			return ErrOwned
		}
		return r.cmd.Start()
	}}
	admissionErr := actual.invoke(func(begin func() error) error { return original.WithEffectStart(ctx, "usque-native-helper", begin) })
	if r.cmd.Process == nil {
		return ErrOwned
	}
	r.armWait()
	r.helper, err = components.ReadNFQWSSupervisionProcessIdentity(r.cmd.Process.Pid)
	if err != nil || r.helper.Group != r.helper.PID || r.helper.BootID != r.offer.Scope.Parent.BootID {
		return ErrOwned
	}
	if admissionErr != nil || actual.outcome != nil || ctx.Err() != nil || original.Current(ctx) != nil || r.assetsCurrent(ctx) != nil {
		return ErrOwned
	}
	if err := r.sendOffer(); err != nil {
		return ErrOwned
	}
	base := frame{Version: 1, Binding: r.offer.digest(), Helper: r.helper}
	ready, err := r.channel.receive()
	base.Kind = "ready"
	if err != nil || !reflect.DeepEqual(ready, base) || original.Current(ctx) != nil || r.facts.Current(ctx) != nil || r.assetsCurrent(ctx) != nil || ctx.Err() != nil {
		return ErrOwned
	}
	base.Kind = "permit"
	if r.channel.send(base) != nil {
		return ErrOwned
	}
	started, err := r.channel.receive()
	base.Kind = "started"
	child := started.Child
	started.Child = components.NFQWSRuntimeProcessIdentity{}
	if err != nil || !reflect.DeepEqual(started, base) || !childMatches(r.offer, r.helper, child) {
		return ErrOwned
	}
	actualChild, err := components.ReadNFQWSRuntimeProcessIdentity(child.PID)
	childNamespace, nsErr := namespaceAt(strconv.Itoa(child.PID))
	if err != nil || nsErr != nil || actualChild != child || childNamespace != r.offer.Scope.Namespace || original.Current(ctx) != nil || r.assetsCurrent(ctx) != nil {
		return ErrOwned
	}
	r.child = child
	r.started = true
	if r.publishPassport(ctx) != nil {
		return ErrOwned
	}
	// Readiness is local factual observation outside the short control lock.
	// Original WithStart still retains close/review admission through this ACK.
	for {
		if original.Current(ctx) != nil || r.facts.Current(ctx) != nil || r.assetsCurrent(ctx) != nil || ctx.Err() != nil {
			return ErrOwned
		}
		request := usquediag.OwnedRuntimeRequest{Root: r.offer.Launch.Process.Dir, Binary: r.offer.Launch.Process.Binary, SOCKSAddress: "127.0.0.1:" + strconv.Itoa(int(r.offer.Scope.Acquisition.Request.SOCKSPort)), Transport: r.offer.Launch.Transport, Endpoint: r.offer.Launch.Endpoint,
			Environment: func(c context.Context) (string, error) { return r.offer.Launch.Environment, c.Err() }}
		if _, err := usquediag.ObserveOwnedUSQUE(ctx, request); err == nil {
			if r.currentLocked(ctx) != nil {
				return ErrOwned
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrOwned
		case <-r.done:
			return ErrOwned
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (r *linuxSession) sendOffer() error {
	if r.offerSent {
		return nil
	}
	if r.channel == nil {
		return ErrOwned
	}
	f := frame{Version: 1, Kind: "offer", Binding: r.offer.digest(), Offer: &r.offer}
	if r.channel.send(f) != nil {
		return ErrOwned
	}
	r.offerSent = true
	return nil
}

func (r *linuxSession) publishPassport(ctx context.Context) error {
	for {
		if ctx.Err() != nil || r.assetsCurrent(ctx) != nil {
			return ErrOwned
		}
		receipt, err := routeidentity.RecordStart(r.child.PID, r.offer.Launch.Process.Binary, r.offer.Launch.Process.Args, r.offer.Launch.Process.MatchArg, r.offer.Launch.ConfigSHA256)
		if err == nil {
			if r.record("engine.pid", []byte(strconv.Itoa(r.child.PID)+"\n")) != nil || r.record("engine.pid"+routeidentity.ReceiptSuffix, receipt) != nil {
				return ErrOwned
			}
			for {
				p, err := routeidentity.Verify(r.offer.Launch.Process.Dir, "usque", "127.0.0.1:"+strconv.Itoa(int(r.offer.Scope.Acquisition.Request.SOCKSPort)))
				if err == nil {
					r.passport = p
					return nil
				}
				select {
				case <-ctx.Done():
					return ErrOwned
				case <-r.done:
					return ErrOwned
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
		select {
		case <-ctx.Done():
			return ErrOwned
		case <-r.done:
			return ErrOwned
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func (r *linuxSession) record(name string, data []byte) error {
	f, err := r.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrOwned
	}
	info, e1 := f.Stat()
	if e1 == nil {
		r.metadata = append(r.metadata, ownedMetadata{name: name, info: info, hash: routeidentity.Hash(data)})
	}
	_, e2 := f.Write(data)
	e3 := f.Sync()
	e4 := f.Close()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return ErrOwned
	}
	return nil
}
func (r *linuxSession) currentLocked(ctx context.Context) error {
	if r.joined || r.released || r.assetsCurrent(ctx) != nil {
		return ErrOwned
	}
	if !r.started {
		return nil
	} // prepared assets are not a running-child claim
	child, e1 := components.ReadNFQWSRuntimeProcessIdentity(r.child.PID)
	helper, e2 := components.ReadNFQWSSupervisionProcessIdentity(r.helper.PID)
	ns, e3 := namespaceAt(strconv.Itoa(r.child.PID))
	p, e4 := routeidentity.Verify(r.offer.Launch.Process.Dir, "usque", "127.0.0.1:"+strconv.Itoa(int(r.offer.Scope.Acquisition.Request.SOCKSPort)))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || child != r.child || helper != r.helper || ns != r.offer.Scope.Namespace || p != r.passport || ctx.Err() != nil {
		return ErrOwned
	}
	return nil
}
func (r *linuxSession) Current(ctx context.Context) error {
	if r.lock(ctx) != nil {
		return ErrOwned
	}
	defer r.unlock()
	return r.currentLocked(ctx)
}

func (r *linuxSession) StopAndJoin(ctx context.Context) error {
	if r.lock(ctx) != nil {
		return ErrOwned
	}
	defer r.unlock()
	if r.joined {
		return r.verifyLocked(ctx)
	}
	if r.cmd == nil || r.cmd.Process == nil {
		r.joined = true
		return ctx.Err()
	}
	r.armWait()
	if r.channel == nil || r.helper.PID != r.cmd.Process.Pid {
		return ErrOwned
	}
	endIO, err := r.channel.withContext(ctx)
	if err != nil {
		return ErrOwned
	}
	defer endIO()
	if r.sendOffer() != nil {
		return ErrOwned
	}
	// STOP carries no new forward permission. It uses the same inherited channel
	// and retained exact helper; queued READY/STARTED are drained, never adopted.
	stop := frame{Version: 1, Kind: "stop", Binding: r.offer.digest(), Helper: r.helper}
	if r.channel.send(stop) != nil {
		return ErrOwned
	}
	for {
		f, err := r.channel.receive()
		if err != nil {
			return ErrOwned
		}
		if f.Binding != r.offer.digest() || f.Helper != r.helper || f.Offer != nil {
			return ErrOwned
		}
		if f.Kind == "ready" || f.Kind == "started" {
			continue
		}
		if f.Kind != "terminal" || !terminalMatches(r.offer, r.helper, f.Child, f.Receipt) || r.child.PID != 0 && r.child != f.Child {
			return ErrOwned
		}
		r.child = f.Child
		r.terminal = f.Receipt
		f.Kind = "ack"
		if r.channel.send(f) != nil {
			return ErrOwned
		}
		r.acknowledged = true
		break
	}
	select {
	case <-ctx.Done():
		return ErrOwned
	case <-r.done:
	}
	if r.waitErr != nil || r.cmd.ProcessState == nil || !r.cmd.ProcessState.Success() {
		return ErrOwned
	}
	r.joined = true
	return r.verifyLocked(ctx)
}
func (r *linuxSession) verifyLocked(ctx context.Context) error {
	if ctx.Err() != nil || !r.joined {
		return ErrOwned
	}
	if r.cmd == nil || r.cmd.Process == nil {
		return nil
	} // actual Start never created a helper
	if !r.acknowledged || !terminalMatches(r.offer, r.helper, r.child, r.terminal) || r.waitErr != nil || r.cmd.ProcessState == nil || !r.cmd.ProcessState.Success() {
		return ErrOwned
	}
	select {
	case <-r.done:
		return nil
	default:
		return ErrOwned
	}
}
func (r *linuxSession) VerifySettled(ctx context.Context) error {
	if r.lock(ctx) != nil {
		return ErrOwned
	}
	defer r.unlock()
	return r.verifyLocked(ctx)
}

func (r *linuxSession) ReleaseAssets(ctx context.Context) error {
	if r.lock(ctx) != nil {
		return ErrOwned
	}
	defer r.unlock()
	if r.released || r.verifyLocked(ctx) != nil {
		return ErrOwned
	}
	if r.root != nil {
		actual, e1 := os.Lstat(r.offer.Launch.Process.Dir)
		anchored, e2 := r.root.Stat(".")
		// An empty own stage can already have been removed by the runner. Its
		// descriptor remains pinned; retained metadata requires a matching path.
		if e2 != nil || !os.SameFile(anchored, r.rootInfo) || e1 != nil && !os.IsNotExist(e1) || e1 == nil && !os.SameFile(actual, r.rootInfo) {
			return ErrOwned
		}
		if _, err := r.root.Lstat("engine.json"); !os.IsNotExist(err) {
			return ErrOwned
		}
		for _, m := range r.metadata {
			info, err := r.root.Lstat(m.name)
			if err != nil || !os.SameFile(info, m.info) {
				return ErrOwned
			}
			f, err := r.root.Open(m.name)
			if err != nil {
				return ErrOwned
			}
			data, readErr := io.ReadAll(io.LimitReader(f, 4097))
			_ = f.Close()
			if readErr != nil || len(data) > 4096 || routeidentity.Hash(data) != m.hash {
				return ErrOwned
			}
			if r.root.Remove(m.name) != nil {
				return ErrOwned
			}
		}
	}
	var e1, e2, e3, e4, e5 error
	if r.channel != nil {
		e1 = r.channel.close()
	}
	if r.binary != nil {
		e2 = r.binary.close()
	}
	if r.config != nil {
		e3 = r.config.close()
	}
	if r.root != nil {
		e4 = r.root.Close()
		r.root = nil
	}
	if r.control != nil {
		e5 = r.control.close()
	}
	if errors.Join(e1, e2, e3, e4, e5) != nil {
		return ErrOwned
	}
	r.released = true
	return nil
}

// Fixed diagnostic label only; neither command nor private error is formatted.
func ownerFailure(stage string) error { return fmt.Errorf("native USQUE %s: %w", stage, ErrOwned) }
