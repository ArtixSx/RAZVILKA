package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var ErrOriginalProcessCleanup = errors.New("original managed child cleanup is unconfirmed")

// OriginalProcessController is an optional isolated-process lifecycle. The
// returned resource comes from the actual Start and its single Cmd.Wait, never
// a PID-file lookup, reconstructed receipt or successful Running(false).
type OriginalProcessController interface {
	StartOriginal(context.Context, ProcessSpec, string) (*OriginalProcess, error)
}

type OriginalProcess struct {
	self       *OriginalProcess
	cmd        *exec.Cmd
	child      *os.Process
	spec       ProcessSpec
	path       string
	args       []string
	port       int
	endpoint   string
	root       *ownedfs.Root
	rootInfo   os.FileInfo
	pidRaw     []byte
	receiptRaw []byte
	receipt    routeidentity.Receipt
	done       chan struct{}
	gate       chan struct{}
	state      *os.ProcessState
	waitErr    error
	cleaned    bool
}

func (*OriginalProcess) String() string   { return "[private original managed child]" }
func (*OriginalProcess) GoString() string { return "[private original managed child]" }

func (OSProcessController) StartOriginal(ctx context.Context, spec ProcessSpec, endpoint string) (*OriginalProcess, error) {
	if runtime.GOOS != "linux" || ctx == nil || ctx.Err() != nil || !spec.RouteProof {
		return nil, ErrOriginalProcessCleanup
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, ErrOriginalProcessCleanup
	}
	host, text, err := net.SplitHostPort(endpoint)
	port, parseErr := strconv.Atoi(text)
	if err != nil || parseErr != nil || host != "127.0.0.1" || port < 1024 || port > 65535 {
		return nil, ErrOriginalProcessCleanup
	}
	spec.Args = slices.Clone(spec.Args)
	var original *OriginalProcess
	err = startManagedProcess(ctx, spec, func(cmd *exec.Cmd, raw []byte) error {
		root, err := ownedfs.Open(spec.Dir)
		if err != nil {
			return ErrOriginalProcessCleanup
		}
		info, err := root.RootInfo()
		pidName, _ := filepath.Rel(spec.Dir, spec.PIDPath)
		pidRaw, pidErr := root.ReadLimited(pidName, 64)
		var receipt routeidentity.Receipt
		if err != nil || pidErr != nil || json.Unmarshal(raw, &receipt) != nil || cmd.Process == nil ||
			receipt.PID != cmd.Process.Pid || string(pidRaw) != strconv.Itoa(cmd.Process.Pid)+"\n" {
			root.Close()
			return ErrOriginalProcessCleanup
		}
		p := &OriginalProcess{cmd: cmd, child: cmd.Process, spec: spec, path: cmd.Path, args: slices.Clone(cmd.Args), port: port, endpoint: endpoint,
			root: root, rootInfo: info, pidRaw: slices.Clone(pidRaw), receiptRaw: slices.Clone(raw), receipt: receipt,
			done: make(chan struct{}), gate: make(chan struct{}, 1)}
		p.self = p
		if p.metadataCurrent(ctx) != nil || p.liveIdentity(ctx) != nil {
			root.Close()
			return ErrOriginalProcessCleanup
		}
		// Exactly one waiter owns this exact child; channel close publishes its
		// terminal Wait result. No other path may call this Cmd's Wait.
		go func() {
			p.waitErr = cmd.Wait()
			p.state = cmd.ProcessState
			close(p.done)
		}()
		_ = root.Close() // Keep identity, not a descriptor, between cleanup calls.
		original = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return original, nil
}

func (p *OriginalProcess) commandCurrent() bool {
	return p != nil && p.self == p && p.cmd != nil && p.child != nil && p.cmd.Process == p.child && p.child.Pid == p.receipt.PID &&
		p.cmd.Path == p.path && p.cmd.Dir == p.spec.Dir && slices.Equal(p.cmd.Args, p.args) &&
		p.cmd.Cancel == nil && len(p.cmd.ExtraFiles) == 0 && p.done != nil && p.gate != nil
}

// A real token for a DIFFERENT launch cannot certify this canary's cleanup.
func (p *OriginalProcess) matches(spec ProcessSpec, endpoint string) bool {
	if !p.commandCurrent() {
		return false
	}
	select {
	case <-p.done:
		return false // An old terminal resource cannot be replayed as a fresh Start.
	default:
	}
	return p.endpoint == endpoint && p.spec.ID == spec.ID && p.spec.Binary == spec.Binary &&
		p.spec.Dir == spec.Dir && p.spec.PIDPath == spec.PIDPath && p.spec.LogPath == spec.LogPath &&
		p.spec.MatchArg == spec.MatchArg && p.spec.RouteProof == spec.RouteProof && slices.Equal(p.spec.Args, spec.Args)
}

func (p *OriginalProcess) metadataCurrent(ctx context.Context) error {
	if !p.commandCurrent() || p.root == nil || ctx.Err() != nil {
		return ErrOriginalProcessCleanup
	}
	named, err := os.Lstat(p.spec.Dir)
	held, heldErr := p.root.RootInfo()
	if err != nil || heldErr != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(p.rootInfo, named) || !os.SameFile(p.rootInfo, held) {
		return ErrOriginalProcessCleanup
	}
	pidName, _ := filepath.Rel(p.spec.Dir, p.spec.PIDPath)
	configName, _ := filepath.Rel(p.spec.Dir, p.spec.MatchArg)
	pid, e1 := p.root.ReadLimited(pidName, 64)
	receipt, e2 := p.root.ReadLimited(pidName+routeidentity.ReceiptSuffix, 4096)
	info, e3 := p.root.Stat(configName)
	if e1 != nil || e2 != nil || e3 != nil || !bytes.Equal(pid, p.pidRaw) || !bytes.Equal(receipt, p.receiptRaw) ||
		!info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 8<<20 {
		return ErrOriginalProcessCleanup
	}
	config, err := p.root.ReadLimited(configName, 8<<20)
	defer clear(config)
	if err != nil || routeidentity.Hash(config) != p.receipt.ConfigHash || ctx.Err() != nil {
		return ErrOriginalProcessCleanup
	}
	return nil
}

func (p *OriginalProcess) liveIdentity(ctx context.Context) error {
	if p.metadataCurrent(ctx) != nil {
		return ErrOriginalProcessCleanup
	}
	current, err := routeidentity.RecordStart(p.receipt.PID, p.spec.Binary, p.spec.Args, p.spec.MatchArg, p.receipt.ConfigHash)
	if err != nil || !bytes.Equal(current, p.receiptRaw) || ctx.Err() != nil {
		return ErrOriginalProcessCleanup
	}
	return nil
}

// StopAndJoin never substitutes a PID-file process for the original child.
// Cancellation, changed identity or uncertain listener state retains both
// ownership files. The ordinary ProcessController.Stop contract is unchanged.
func (p *OriginalProcess) StopAndJoin(ctx context.Context) error {
	if !p.commandCurrent() || ctx == nil || ctx.Err() != nil {
		return ErrOriginalProcessCleanup
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrOriginalProcessCleanup
	}
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return ErrOriginalProcessCleanup
	}
	if p.cleaned {
		return originalProcessListenerAbsent(ctx, p.port)
	}
	root, err := ownedfs.Open(p.spec.Dir)
	if err != nil {
		return ErrOriginalProcessCleanup
	}
	p.root = root
	defer root.Close()
	if p.metadataCurrent(ctx) != nil {
		return ErrOriginalProcessCleanup
	}
	select {
	case <-p.done:
	default:
		if p.liveIdentity(ctx) != nil {
			return ErrOriginalProcessCleanup
		}
		if err := p.child.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return ErrOriginalProcessCleanup
		}
		grace := time.NewTimer(4 * time.Second)
		defer grace.Stop()
		select {
		case <-p.done:
		case <-ctx.Done():
			return ErrOriginalProcessCleanup
		case <-grace.C:
			if p.liveIdentity(ctx) != nil {
				return ErrOriginalProcessCleanup
			}
			if err := p.child.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return ErrOriginalProcessCleanup
			}
		}
	}
	select {
	case <-p.done:
	case <-ctx.Done():
		return ErrOriginalProcessCleanup
	}
	if !p.commandCurrent() || !xraySelectedTCPWaitResult(p.receipt.PID, p.state, p.waitErr) || p.metadataCurrent(ctx) != nil ||
		originalProcessPIDAbsent(p.receipt.PID) != nil || originalProcessListenerAbsent(ctx, p.port) != nil ||
		p.metadataCurrent(ctx) != nil || originalProcessPIDAbsent(p.receipt.PID) != nil {
		return ErrOriginalProcessCleanup
	}
	pidName, _ := filepath.Rel(p.spec.Dir, p.spec.PIDPath)
	if p.root.Remove(pidName+routeidentity.ReceiptSuffix) != nil || p.root.Remove(pidName) != nil {
		return ErrOriginalProcessCleanup
	}
	p.cleaned = true
	return nil
}
