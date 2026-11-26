//go:build linux

package app

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// nfqws2HookWatch is one inotify watch on the stock hook path. A replaced,
// removed or moved file drops the watch; it is re-added with backoff, so a
// package reinstall re-arms the hint and an absent file costs one syscall
// per backoff period.
type nfqws2HookWatch struct {
	fd, wd   int
	path     string
	dev, ino uint64
	rearmAt  time.Time
	backoff  time.Duration
	timing   nfqws2HookHintTiming
}

const nfqws2HookWatchMask = unix.IN_OPEN | unix.IN_CLOSE_NOWRITE | unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF

func (w *nfqws2HookWatch) arm(now time.Time) error {
	wd, err := unix.InotifyAddWatch(w.fd, w.path, nfqws2HookWatchMask)
	var stat unix.Stat_t
	if err == nil {
		if err = unix.Stat(w.path, &stat); err != nil {
			_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
		}
	}
	if err != nil {
		w.backoff = min(max(w.timing.rearmMin, 2*w.backoff), w.timing.rearmMax)
		w.rearmAt = now.Add(w.backoff)
		return err
	}
	w.wd, w.dev, w.ino, w.backoff = wd, uint64(stat.Dev), uint64(stat.Ino), 0
	return nil
}

// drop forgets the current watch and retries the path at once; a failed
// retry then backs off.
func (w *nfqws2HookWatch) drop(now time.Time, remove bool) {
	if remove && w.wd >= 0 {
		_, _ = unix.InotifyRmWatch(w.fd, uint32(w.wd))
	}
	w.wd, w.rearmAt = -1, now
}

// replaced reports that the path no longer names the watched file.
func (w *nfqws2HookWatch) replaced() bool {
	var stat unix.Stat_t
	return unix.Stat(w.path, &stat) != nil || uint64(stat.Dev) != w.dev || uint64(stat.Ino) != w.ino
}

// events reads one inotify buffer. Only an open of the watched file, or a
// queue overflow that may have hidden one, is a hint.
func (w *nfqws2HookWatch) events(data []byte, now time.Time, settle *nfqws2HookSettle) {
	for len(data) >= unix.SizeofInotifyEvent {
		wd := int(int32(binary.NativeEndian.Uint32(data[:4])))
		mask := binary.NativeEndian.Uint32(data[4:8])
		size := int(binary.NativeEndian.Uint32(data[12:16]))
		if size > len(data)-unix.SizeofInotifyEvent {
			return
		}
		data = data[unix.SizeofInotifyEvent+size:]
		if mask&unix.IN_Q_OVERFLOW != 0 {
			settle.event(now)
			continue
		}
		if wd != w.wd || w.wd < 0 {
			continue // A watch dropped earlier still reports its removal.
		}
		if mask&(unix.IN_OPEN|unix.IN_CLOSE_NOWRITE) != 0 {
			settle.event(now)
		}
		switch {
		case mask&unix.IN_IGNORED != 0:
			w.drop(now, false)
		case mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_UNMOUNT) != 0:
			w.drop(now, true)
		case mask&unix.IN_ATTRIB != 0 && w.replaced():
			w.drop(now, true)
		}
	}
}

// runNFQWS2HookHint watches the stock hook until ctx ends. Any failure only
// disables the hint: the 30-second node-recovery schedule remains.
func runNFQWS2HookHint(ctx context.Context, path string, timing nfqws2HookHintTiming, wake func() bool) {
	if path == "" || wake == nil || ctx.Err() != nil {
		return
	}
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		log.Print("NFQWS2 hook hint is unavailable; the 30-second recovery check remains")
		return
	}
	// The nonblocking descriptor joins the runtime poller, so a read
	// deadline both times the settle and ends the wait on cancellation.
	file := os.NewFile(uintptr(fd), "nfqws2-hook-hint")
	defer file.Close()
	stop := context.AfterFunc(ctx, func() { _ = file.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	w := nfqws2HookWatch{fd: fd, wd: -1, path: path, timing: timing}
	settle := nfqws2HookSettle{timing: timing}
	buffer := make([]byte, 16<<10)
	logged := false
	for {
		now := time.Now()
		if w.wd < 0 && !now.Before(w.rearmAt) {
			if err := w.arm(now); err != nil && !logged {
				logged = true
				log.Printf("NFQWS2 hook hint is not armed (%v); the 30-second recovery check remains", err)
			}
		}
		settle.fire(now, wake)
		var deadline time.Time
		if at, pending := settle.due(); pending {
			deadline = at
		}
		if w.wd < 0 && (deadline.IsZero() || w.rearmAt.Before(deadline)) {
			deadline = w.rearmAt
		}
		if file.SetReadDeadline(deadline) != nil || ctx.Err() != nil {
			return
		}
		n, err := file.Read(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if err != nil {
			log.Print("NFQWS2 hook hint stopped; the 30-second recovery check remains")
			return
		}
		w.events(buffer[:n], time.Now(), &settle)
	}
}
