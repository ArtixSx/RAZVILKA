package operationgate

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// ControlEpochReference is a comparison value, never an admission. The held
// protected root/lock incarnation, same Gate and original operation capability
// cannot be reconstructed from it. It does not authorize a self-update.
type ControlEpochReference struct {
	InstallationID string
	Sequence       uint64
}

// ControlEpochReview retains the actual protected control directory and the
// permanent lock inode. Every forward use requires a live original exclusive
// operation context; its reference grants no Store or provider permission.
type ControlEpochReview struct {
	self   *ControlEpochReview
	mu     sync.Mutex
	gate   *Gate
	dir    *controlDirectory
	lock   *os.File
	info   os.FileInfo
	ref    ControlEpochReference
	closed bool
}

func (*ControlEpochReview) String() string   { return "[private control epoch review]" }
func (*ControlEpochReview) GoString() string { return "[private control epoch review]" }

// ReviewControlEpoch only reads existing control state under actual original
// exclusive admission. Missing state never initializes authority.
func (g *Gate) ReviewControlEpoch(ctx context.Context, path string) (*ControlEpochReview, error) {
	var review *ControlEpochReview
	err := g.WithExclusiveContext(ctx, func() error {
		d, err := openControlDirectory(path, false)
		if err != nil {
			return ErrSelfUpdateStopJournal
		}
		keep := false
		defer func() {
			if !keep {
				d.close()
			}
		}()
		f, err := d.root.OpenFile(selfControlLock, os.O_RDONLY|controlFileFlags(), 0)
		if err != nil {
			return ErrSelfUpdateStopJournal
		}
		defer func() {
			if !keep {
				_ = f.Close()
			}
		}()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || !controlPrivate(info) {
			return ErrSelfUpdateStopJournal
		}
		r, err := readControlCurrent(d)
		if err != nil || checkControlRequest(d, r) != nil {
			return ErrSelfUpdateStopJournal
		}
		review = &ControlEpochReview{gate: g, dir: d, lock: f, info: info,
			ref: ControlEpochReference{InstallationID: r.InstallationID, Sequence: r.Sequence}}
		review.self = review
		if err := review.check(ctx); err != nil {
			review = nil
			return err
		}
		keep = true
		return nil
	})
	if err != nil {
		if review != nil {
			_ = review.Close()
		}
		return nil, err
	}
	return review, nil
}

func (r *ControlEpochReview) Reference() ControlEpochReference {
	if r == nil || r.self != r {
		return ControlEpochReference{}
	}
	return r.ref
}

// MatchesControlRoot is comparison data only. Forward use still calls Current
// or a short admission on this SAME original handle; equal epochs at another
// root do not authorize publication through the configured owner.
func (r *ControlEpochReview) MatchesControlRoot(path string) bool {
	if r == nil || r.self != r {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.dir != nil && r.dir.path == path
}

// Current reads the SAME retained protected owner, epoch and permanent marker.
// Fresh same-Gate operations may compare a durable consent epoch, but Current
// itself does not grant consent, certify a Store or authorize an effect.
func (r *ControlEpochReview) Current(ctx context.Context) error {
	if r == nil || r.self != r || r.gate == nil {
		return ErrSelfUpdateStopChanged
	}
	return r.gate.WithExclusiveContext(ctx, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.check(ctx)
	})
}

// ReviewExclusiveCleanup captures only this SAME original operation's cleanup
// lifetime while the retained control owner is still ready, before effects or
// cancellation. It reuses the existing cleanup review; no background admission,
// forward context, process/file ownership or completion proof is created.
func (r *ControlEpochReview) ReviewExclusiveCleanup(ctx context.Context) (*ExclusiveCleanupReview, error) {
	if r == nil || r.self != r || r.gate == nil {
		return nil, ErrSelfUpdateStopChanged
	}
	var cleanup *ExclusiveCleanupReview
	err := r.gate.WithExclusiveContext(ctx, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if err := r.check(ctx); err != nil {
			return err
		}
		var err error
		cleanup, err = r.gate.ReviewExclusiveCleanup(ctx)
		return errors.Join(err, r.check(ctx))
	})
	if err != nil {
		return nil, err
	}
	return cleanup, nil
}

// CurrentForCleanup only compares this SAME retained control incarnation and
// ready epoch or its validated durable Stop successor. It grants no Gate
// admission or effect. A producer calls it inside its pre-issued original
// ExclusiveCleanupReview.WithCurrent, and independently proves exact ownership
// and completion before releasing the original operation.
func (r *ControlEpochReview) CurrentForCleanup(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil {
		return ErrSelfUpdateStopChanged
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return errors.Join(ErrSelfUpdateStopChanged, ctx.Err())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkWithMarkerMode(ctx, r.lock, true)
}

// WithStart linearizes ONLY an actual bounded Cmd.Start syscall with durable
// Stop. The caller must already retain its exact command/review/Store/owner
// binding; this primitive grants none of them. The synchronous callback must
// not call this review or perform readiness, Wait, fsync or cleanup. No Gate
// mutex is held while acquiring or holding the protected control lock.
func (r *ControlEpochReview) WithStart(ctx context.Context, begin func() error) error {
	return r.withShortEffect(ctx, begin)
}

// WithRename linearizes only one synchronous bounded rename syscall with
// durable Stop under this SAME retained control owner and original operation.
// The caller's exact existing file-target lease must stage/write/file-sync and
// verify its preimage before admission; directory sync/readback/repair happen
// afterwards. rename MUST NOT call this review, Store/Gate, fsync, Wait or any
// whole publication protocol. This method grants no file, source or scope.
func (r *ControlEpochReview) WithRename(ctx context.Context, rename func() error) error {
	if ctx == nil {
		return ErrSelfUpdateStopChanged
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return errors.Join(ErrSelfUpdateStopChanged, ctx.Err())
	}
	return r.withShortEffect(ctx, rename)
}

// WithRemove linearizes only one synchronous bounded removal syscall with
// durable Stop under this SAME retained control owner and original operation.
// The caller must retain its exact file-target writer lease and verify the
// preimage before admission; directory sync and readback happen afterwards.
// remove MUST NOT call this review, Store/Gate, fsync or a recovery protocol.
// This method grants no file ownership or permission to delete another image.
func (r *ControlEpochReview) WithRemove(ctx context.Context, remove func() error) error {
	if ctx == nil {
		return ErrSelfUpdateStopChanged
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return errors.Join(ErrSelfUpdateStopChanged, ctx.Err())
	}
	return r.withShortEffect(ctx, remove)
}

func (r *ControlEpochReview) withShortEffect(ctx context.Context, begin func() error) error {
	if r == nil || r.self != r || r.gate == nil || begin == nil {
		return ErrSelfUpdateStopChanged
	}
	return r.gate.WithExclusiveContext(ctx, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if err := r.check(ctx); err != nil {
			return err
		}
		locked, _, err := lockControlFile(ctx, r.dir)
		if err != nil {
			return err
		}
		defer locked.Close()
		if err := r.checkWithMarker(ctx, locked); err != nil {
			return err
		}
		err = begin()
		return errors.Join(err, r.checkWithMarker(ctx, locked))
	})
}

func (r *ControlEpochReview) check(ctx context.Context) error {
	return r.checkWithMarker(ctx, r.lock)
}

func (r *ControlEpochReview) checkWithMarker(ctx context.Context, markerReader *os.File) error {
	return r.checkWithMarkerMode(ctx, markerReader, false)
}

func (r *ControlEpochReview) checkWithMarkerMode(ctx context.Context, markerReader *os.File, allowStopped bool) error {
	if ctx == nil || r.closed || r.dir == nil || r.lock == nil || r.info == nil {
		return ErrSelfUpdateStopChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.checkHeldOwner(markerReader); err != nil {
		return err
	}
	record, err := readControlCurrent(r.dir)
	if err != nil || checkControlRequest(r.dir, record) != nil {
		return ErrSelfUpdateStopJournal
	}
	if record.Stopped && !allowStopped {
		return ErrSelfUpdateStopped
	}
	expectedSequence := r.ref.Sequence
	if allowStopped && record.Stopped {
		if expectedSequence == ^uint64(0) {
			return ErrSelfUpdateStopChanged
		}
		expectedSequence++
	}
	if record.InstallationID != r.ref.InstallationID || record.Sequence != expectedSequence {
		return ErrSelfUpdateStopChanged
	}
	if err := r.checkHeldOwner(markerReader); err != nil {
		return err
	}
	return ctx.Err()
}

func (r *ControlEpochReview) checkHeldOwner(markerReader *os.File) error {
	if r.dir.unchanged() != nil {
		return ErrSelfUpdateStopJournal
	}
	root, err := os.Lstat(r.dir.path)
	if err != nil || !root.IsDir() || !controlPrivate(root) || root.Mode()&os.ModeSymlink != 0 {
		return ErrSelfUpdateStopJournal
	}
	held, err := r.lock.Stat()
	current, currentErr := r.dir.root.Stat(selfControlLock)
	if err != nil || currentErr != nil || !os.SameFile(r.info, held) || !os.SameFile(held, current) || !controlPrivate(current) || !current.Mode().IsRegular() {
		return ErrSelfUpdateStopJournal
	}
	marker := make([]byte, len(selfControlMarker)+1)
	markerInfo, err := markerReader.Stat()
	if err != nil || !os.SameFile(held, markerInfo) {
		return ErrSelfUpdateStopJournal
	}
	n, err := markerReader.ReadAt(marker, 0)
	if err != nil && !errors.Is(err, io.EOF) || string(marker[:n]) != selfControlMarker {
		return ErrSelfUpdateStopJournal
	}
	return nil
}

// Close joins a concurrent short Current/Start use and closes both retained
// descriptors. It does not release a Gate lease or settle an effect. The actual
// owner first proves Stop/Wait/ECHILD and then releases original admission.
func (r *ControlEpochReview) Close() error {
	if r == nil {
		return nil
	}
	if r.self != r {
		return ErrSelfUpdateStopChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.lock != nil {
		err = r.lock.Close()
	}
	if r.dir != nil {
		err = errors.Join(err, r.dir.root.Close())
	}
	return err
}
