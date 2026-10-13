package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const candidateKnownAbsentPIDEffect = "candidate-known-absent-pid"

// This source belongs to the original H scope, not to a process receipt.
// The start S's sole actual Wait establishes completion only; it grants no
// live acceptance and cannot be used by a fresh stop S or a cold observer.
type candidateStartWait struct {
	self                                   *candidateStartWait
	owner                                  *ordinaryInstallerJoin
	worker                                 *exec.Cmd
	process                                *os.Process
	state                                  *os.ProcessState
	parent, supervisor                     fileProcess
	mu                                     sync.Mutex
	joined                                 chan struct{}
	reported, successful, failed, consumed bool
	ready                                  fileCommandReceipt
	pid                                    *candidatePIDImage
	record                                 updateRecord
	review                                 fileReview
	identity                               fileHelperIdentity
}

func beginCandidateStartWait(ctx context.Context, a *SelfUpdateFileAdapter, id string, worker *exec.Cmd, parent, supervisor fileProcess) (*candidateStartWait, error) {
	o, err := ordinaryInstallerOwner(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if ctx != o.held || worker == nil || worker.Process == nil || worker.ProcessState != nil || !validFileProcess(parent) || !validFileProcess(supervisor) ||
		parent.PID != os.Getpid() || supervisor.PID != worker.Process.Pid || parent.PID == supervisor.PID || parent.Boot != supervisor.Boot || parent.ExecutableSHA256 != supervisor.ExecutableSHA256 {
		return nil, o.poison(nil)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.candidate != nil || o.current(ctx, a, id) != nil {
		return nil, o.poison(nil)
	}
	w := &candidateStartWait{owner: o, worker: worker, process: worker.Process, parent: parent, supervisor: supervisor, joined: make(chan struct{})}
	w.self = w
	o.candidate = w
	return w, nil
}

func (w *candidateStartWait) current(ctx context.Context) error {
	if w == nil || w.self != w || w.owner == nil || w.failed || w.consumed || ctx != w.owner.held {
		return ErrFileCommandUnsettled
	}
	return w.owner.current(ctx, w.owner.adapter, w.owner.id)
}

// Called only by the existing sole worker.Wait goroutine, before done.
func (w *candidateStartWait) observeWait(err error) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.self != w || w.reported {
		w.failed = true
		return
	}
	w.reported = true
	state := w.worker.ProcessState
	w.successful = err == nil && w.worker.Process == w.process && state != nil && state.Pid() == w.supervisor.PID && state.Exited() && state.Success() && state.ExitCode() == 0
	w.state = state
	close(w.joined)
}

func (w *candidateStartWait) rememberReady(ctx context.Context, ready fileCommandReceipt, pid *candidatePIDImage) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.current(ctx); err != nil {
		return err
	}
	if w.ready != (fileCommandReceipt{}) || pid == nil || !validFileCommandReceipt(ready) || ready.ID != w.owner.id || ready.Command != "start-candidate-panel" || ready.State != "runtime-ready" || ready.Parent != w.parent || ready.Supervisor != w.supervisor ||
		ready.Runtime.PID == ready.Parent.PID || ready.Runtime.PID == ready.Supervisor.PID || ready.Runtime.PID == ready.DirectPID || pid.pid != ready.Runtime.PID {
		w.failed = true
		return ErrFileCommandUnsettled
	}
	w.ready, w.pid = ready, pid
	return nil
}

// Caller holds w.mu. A successful start shell or JSON ECHILD alone is not a
// completed source: H must have joined this exact original supervisor too.
func (w *candidateStartWait) completed(ctx context.Context, final fileCommandReceipt) error {
	if err := w.current(ctx); err != nil {
		return err
	}
	if !w.reported || !w.successful || w.worker.Process != w.process || w.worker.ProcessState != w.state || w.state == nil || w.pid == nil || w.ready.State != "runtime-ready" || !validFileCommandReceipt(final) || final.ID != w.owner.id || final.Command != "start-candidate-panel" || final.State != "reaped" || !final.WaitECHILD || final.Cancelled || final.ExitCode != 0 ||
		final.Parent != w.ready.Parent || final.Supervisor != w.ready.Supervisor || final.Runtime != w.ready.Runtime || final.DirectPID != w.ready.DirectPID || final.Reaped <= w.ready.Reaped {
		return ErrFileCommandUnsettled
	}
	return nil
}

func (w *candidateStartWait) close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pid != nil {
		w.pid.close()
		w.pid = nil
	}
}

// Only the native H caller supplies the fresh checks and admitted effect.
// Keeping these local makes refusal tests deterministic; there is no global
// hook, serialized grant, or public caller-provided claim of absence.
func executeCandidateCleanup(ctx context.Context, w *candidateStartWait, final fileCommandReceipt, check func() error, admission func(func() error) error, remove func(*candidatePIDImage) error) error {
	if w == nil || check == nil || admission == nil || remove == nil || !w.mu.TryLock() {
		return ErrFileCommandUnsettled
	}
	defer w.mu.Unlock()
	if err := w.completed(ctx, final); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	exists, err := w.pid.observe()
	if err != nil {
		return err
	}
	if exists {
		var gate sync.Mutex
		called, repeated, retired := false, false, false
		err = admission(func() error {
			gate.Lock()
			defer gate.Unlock()
			if retired || called {
				repeated = true
				return ErrFileCommandUnsettled
			}
			called = true
			if err := w.completed(ctx, final); err != nil {
				return err
			}
			if err := check(); err != nil {
				return err
			}
			exists, err := w.pid.observe()
			if err != nil {
				return err
			}
			if !exists {
				return nil
			}
			return remove(w.pid)
		})
		gate.Lock()
		retired = true
		invalid := !called || repeated
		gate.Unlock()
		if invalid {
			return errors.Join(ErrFileCommandUnsettled, err)
		}
		if err != nil {
			return err
		}
	}
	if err := check(); err != nil {
		return err
	}
	if exists, err := w.pid.observe(); err != nil || exists {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := w.completed(ctx, final); err != nil {
		return err
	}
	w.consumed = true
	return nil
}

// Retain the original ready PID-file and parent descriptors until H leaves
// its scope. Later removal is permitted only for these exact unchanged bytes
// and inode, never for an equivalent new file or a receipt-supplied PID.
type candidatePIDImage struct {
	directory    string
	root         *os.Root
	file         *os.File
	parent, info os.FileInfo
	data         []byte
	pid          int
}

func captureCandidatePID(directory string, pid, flags int) (*candidatePIDImage, error) {
	p := &candidatePIDImage{directory: directory, pid: pid}
	var err error
	p.root, err = os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			p.close()
		}
	}()
	p.parent, err = p.root.Stat(".")
	if err != nil {
		return nil, err
	}
	pathParent, err := os.Lstat(directory)
	if err != nil || !pathParent.IsDir() || pathParent.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathParent, p.parent) {
		return nil, ErrFileProtocol
	}
	p.info, err = p.root.Lstat("razvilka.pid")
	if err != nil || !p.info.Mode().IsRegular() || p.info.Size() <= 0 || p.info.Size() > 32 {
		return nil, ErrFileProtocol
	}
	p.file, err = p.root.OpenFile("razvilka.pid", os.O_RDONLY|flags, 0)
	if err != nil {
		return nil, err
	}
	info, err := p.file.Stat()
	if err != nil || !os.SameFile(info, p.info) {
		return nil, ErrFileProtocol
	}
	p.data, err = candidatePIDBytes(p.file)
	if err != nil {
		return nil, err
	}
	numeric, err := strconv.Atoi(strings.TrimSpace(string(p.data)))
	if err != nil || numeric != pid || pid <= 1 {
		return nil, ErrFileProtocol
	}
	if exists, err := p.observe(); err != nil || !exists {
		return nil, errors.Join(ErrFileProtocol, err)
	}
	keep = true
	return p, nil
}

func candidatePIDBytes(file *os.File) ([]byte, error) {
	data := make([]byte, 33)
	n, err := file.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == 0 || n > 32 {
		return nil, ErrFileProtocol
	}
	return data[:n], nil
}

func (p *candidatePIDImage) observe() (bool, error) {
	if p == nil || p.root == nil || p.file == nil {
		return false, ErrFileProtocol
	}
	parent, err := os.Lstat(p.directory)
	if err != nil || !os.SameFile(parent, p.parent) || parent.Mode() != p.parent.Mode() {
		return false, ErrFileProtocol
	}
	bound, err := p.root.Stat(".")
	if err != nil || !os.SameFile(bound, p.parent) {
		return false, ErrFileProtocol
	}
	info, err := p.file.Stat()
	if err != nil || !os.SameFile(info, p.info) || info.Mode() != p.info.Mode() || info.Size() != p.info.Size() || !info.ModTime().Equal(p.info.ModTime()) {
		return false, ErrFileProtocol
	}
	data, err := candidatePIDBytes(p.file)
	if err != nil || !bytes.Equal(data, p.data) {
		return false, ErrFileProtocol
	}
	current, err := p.root.Lstat("razvilka.pid")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(current, p.info) || current.Mode() != p.info.Mode() || current.Size() != p.info.Size() {
		return false, ErrFileProtocol
	}
	return true, nil
}

func (p *candidatePIDImage) close() {
	if p.file != nil {
		p.file.Close()
		p.file = nil
	}
	if p.root != nil {
		p.root.Close()
		p.root = nil
	}
}
