package operationgate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const SelfUpdateControlSchema = 1
const selfControlOwner = "razvilka-control-authority-v1"
const selfControlCurrent = "current-v1.json"
const selfControlLock = ".control.lock"
const selfControlMarker = "RAZVILKA control authority v1\n"

var ErrSelfUpdateStopped = errors.New("application effect authority is durably stopped")
var ErrSelfUpdateStopJournal = errors.New("application control authority requires review")
var ErrSelfUpdateStopChanged = errors.New("application control authority changed")

// Sequence is the independent control epoch, outside rollback images. A Stop
// request revokes every helper, regardless of TransactionID. There is no
// implicit clear/reset or Resume API in this module.
type SelfUpdateStop struct {
	Schema         int    `json:"schema"`
	Owner          string `json:"owner"`
	InstallationID string `json:"installation_id"`
	Sequence       uint64 `json:"sequence"`
	TransactionID  string `json:"transaction_id,omitempty"`
	ConfigRevision uint64 `json:"config_revision,omitempty"`
	State          string `json:"state"`
	Stopped        bool   `json:"stopped"`
	Digest         string `json:"digest"`
}

type controlDirectory struct {
	root    *ownedfs.Root
	path    string
	info    os.FileInfo
	created bool
}

func (d *controlDirectory) close() { _ = d.root.Close() }
func (d *controlDirectory) unchanged() error {
	info, err := os.Lstat(d.path)
	if err != nil || !os.SameFile(d.info, info) || info.Mode()&os.ModeSymlink != 0 {
		return ErrSelfUpdateStopJournal
	}
	return nil
}

func controlHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

func openControlDirectory(path string, create bool) (*controlDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == filepath.VolumeName(path)+string(filepath.Separator) {
		return nil, ErrSelfUpdateStopJournal
	}
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) && create {
		parent, parentErr := ownedfs.Open(filepath.Dir(path))
		if parentErr != nil {
			return nil, ErrSelfUpdateStopJournal
		}
		defer parent.Close()
		if err = parent.MkdirAll(filepath.Base(path), 0700); err != nil {
			return nil, ErrSelfUpdateStopJournal
		}
		if err = controlSync(parent); err != nil {
			return nil, ErrSelfUpdateStopJournal
		}
		created = true
		info, err = os.Lstat(path)
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !controlPrivate(info) {
		return nil, ErrSelfUpdateStopJournal
	}
	r, err := ownedfs.Open(path)
	if err != nil {
		return nil, ErrSelfUpdateStopJournal
	}
	d := &controlDirectory{root: r, path: path, info: info, created: created}
	if err = d.unchanged(); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

func readControlBytes(d *controlDirectory, name string, limit int64) ([]byte, error) {
	info, err := d.root.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !controlPrivate(info) {
		return nil, ErrSelfUpdateStopJournal
	}
	return d.root.ReadLimited(name, limit)
}

func sealControl(record SelfUpdateStop) ([]byte, error) {
	record.Digest = ""
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	record.Digest = hex.EncodeToString(hash[:])
	return json.Marshal(record)
}

func decodeControl(raw []byte) (SelfUpdateStop, error) {
	var r SelfUpdateStop
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF || r.Schema != SelfUpdateControlSchema || r.Owner != selfControlOwner || !controlHex(r.InstallationID, 32) || r.Sequence == 0 || !controlHex(r.Digest, 64) {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	if r.Stopped {
		if !controlHex(r.TransactionID, 32) || r.ConfigRevision == ^uint64(0) || r.State != "requested" && r.State != "cleanup-unknown" && r.State != "observed-stopped" {
			return SelfUpdateStop{}, ErrSelfUpdateStopJournal
		}
	} else if r.State != "ready" || r.Sequence != 1 || r.TransactionID != "" || r.ConfigRevision != 0 {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	sealed, err := sealControl(r)
	if err != nil || !bytes.Equal(raw, sealed) {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	return r, nil
}

func readControlCurrent(d *controlDirectory) (SelfUpdateStop, error) {
	raw, err := readControlBytes(d, selfControlCurrent, 4096)
	if err != nil {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	return decodeControl(raw)
}

func controlRequestName(r SelfUpdateStop) string { return "stop-" + r.TransactionID + ".json" }
func checkControlRequest(d *controlDirectory, r SelfUpdateStop) error {
	if !r.Stopped {
		return nil
	}
	raw, err := readControlBytes(d, controlRequestName(r), 4096)
	if err != nil {
		return ErrSelfUpdateStopJournal
	}
	request, err := decodeControl(raw)
	if err != nil || !request.Stopped || request.State != "requested" || request.InstallationID != r.InstallationID || request.Sequence != r.Sequence || request.TransactionID != r.TransactionID || request.ConfigRevision != r.ConfigRevision {
		return ErrSelfUpdateStopJournal
	}
	return nil
}

// Read is bounded and never creates a directory, file, lock, or Store. A
// present but incomplete directory is fenced, including the marker-only gap.
func ReadSelfUpdateStop(ctx context.Context, path string) (SelfUpdateStop, bool, error) {
	if err := ctx.Err(); err != nil {
		return SelfUpdateStop{}, false, err
	}
	d, err := openControlDirectory(path, false)
	if errors.Is(err, os.ErrNotExist) {
		return SelfUpdateStop{}, false, nil
	}
	if err != nil {
		return SelfUpdateStop{}, false, ErrSelfUpdateStopJournal
	}
	defer d.close()
	marker, markerErr := readControlBytes(d, selfControlLock, int64(len(selfControlMarker)))
	if markerErr != nil || string(marker) != selfControlMarker {
		return SelfUpdateStop{}, false, ErrSelfUpdateStopJournal
	}
	r, err := readControlCurrent(d)
	if err != nil {
		return SelfUpdateStop{}, false, err
	}
	if err = checkControlRequest(d, r); err != nil {
		return r, true, err
	}
	if err = d.unchanged(); err != nil {
		return r, true, err
	}
	return r, true, ctx.Err()
}

func lockControl(ctx context.Context, d *controlDirectory) (func(), bool, error) {
	var f *os.File
	var err error
	created := false
	if d.created {
		f, err = d.root.OpenFile(selfControlLock, os.O_RDWR|os.O_CREATE|os.O_EXCL|controlFileFlags(), 0600)
		created = err == nil
	}
	if !d.created || errors.Is(err, os.ErrExist) {
		f, err = d.root.OpenFile(selfControlLock, os.O_RDWR|controlFileFlags(), 0600)
	}
	if err != nil {
		return nil, false, ErrSelfUpdateStopJournal
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !controlPrivate(info) {
		return nil, false, ErrSelfUpdateStopJournal
	}
	for {
		if err = ctx.Err(); err != nil {
			return nil, false, err
		}
		err = controlFileLock(f)
		if err == nil {
			break
		}
		if !errors.Is(err, errControlLockBusy) {
			return nil, false, ErrSelfUpdateStopJournal
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, false, ctx.Err()
		case <-timer.C:
		}
	}
	current, err := d.root.Stat(selfControlLock)
	if err != nil || !os.SameFile(info, current) || d.unchanged() != nil {
		return nil, false, ErrSelfUpdateStopJournal
	}
	if created {
		if _, err = f.WriteString(selfControlMarker); err != nil {
			return nil, false, ErrSelfUpdateStopJournal
		}
		if f.Sync() != nil || controlSync(d.root) != nil {
			return nil, false, ErrSelfUpdateStopJournal
		}
	} else {
		marker, err := io.ReadAll(io.LimitReader(f, int64(len(selfControlMarker))+1))
		if err != nil || string(marker) != selfControlMarker {
			return nil, false, ErrSelfUpdateStopJournal
		}
	}
	keep = true
	return func() { _ = f.Close() }, created, nil
}

func writeControl(d *controlDirectory, name string, r SelfUpdateStop) error {
	if d.unchanged() != nil {
		return ErrSelfUpdateStopJournal
	}
	raw, err := sealControl(r)
	if err != nil || d.root.WriteAtomic(name, raw, 0600) != nil || controlSync(d.root) != nil {
		return ErrSelfUpdateStopJournal
	}
	return d.unchanged()
}

func controlInstallationID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", ErrSelfUpdateStopJournal
	}
	return hex.EncodeToString(id[:]), nil
}

// Initialize is explicit trusted Prepare/installation bootstrap only. It
// never clears an existing Stop, including after crash/restart/rollback.
func InitializeSelfUpdateControl(ctx context.Context, path string) (SelfUpdateStop, error) {
	if err := ctx.Err(); err != nil {
		return SelfUpdateStop{}, err
	}
	d, err := openControlDirectory(path, true)
	if err != nil {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	defer d.close()
	release, markerCreated, err := lockControl(ctx, d)
	if err != nil {
		return SelfUpdateStop{}, err
	}
	defer release()
	r, err := readControlCurrent(d)
	if err == nil {
		if checkControlRequest(d, r) != nil {
			return SelfUpdateStop{}, ErrSelfUpdateStopJournal
		}
		if r.Stopped {
			return r, ErrSelfUpdateStopped
		}
		return r, ctx.Err()
	}
	if !d.created || !markerCreated {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	id, err := controlInstallationID()
	if err != nil {
		return SelfUpdateStop{}, err
	}
	r = SelfUpdateStop{Schema: SelfUpdateControlSchema, Owner: selfControlOwner, InstallationID: id, Sequence: 1, State: "ready"}
	if err = writeControl(d, selfControlCurrent, r); err != nil {
		return SelfUpdateStop{}, err
	}
	raw, _ := sealControl(r)
	r, _ = decodeControl(raw)
	return r, ctx.Err()
}

func RequestSelfUpdateStop(ctx context.Context, path, id string, revision uint64) (SelfUpdateStop, error) {
	return requestSelfUpdateStop(ctx, path, id, revision, nil)
}

func requestSelfUpdateStop(ctx context.Context, path, id string, revision uint64, fault func(string) error) (SelfUpdateStop, error) {
	if err := ctx.Err(); err != nil {
		return SelfUpdateStop{}, err
	}
	if !controlHex(id, 32) || revision == ^uint64(0) {
		return SelfUpdateStop{}, ErrSelfUpdateStopChanged
	}
	d, err := openControlDirectory(path, true)
	if err != nil {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	defer d.close()
	release, markerCreated, err := lockControl(ctx, d)
	if err != nil {
		return SelfUpdateStop{}, err
	}
	defer release()
	r, readErr := readControlCurrent(d)
	if readErr != nil {
		if !d.created || !markerCreated {
			return SelfUpdateStop{}, ErrSelfUpdateStopJournal
		}
		installation, err := controlInstallationID()
		if err != nil {
			return SelfUpdateStop{}, err
		}
		r = SelfUpdateStop{Schema: SelfUpdateControlSchema, Owner: selfControlOwner, InstallationID: installation}
	}
	if r.Stopped {
		if r.TransactionID != id || r.ConfigRevision != revision {
			return SelfUpdateStop{}, ErrSelfUpdateStopChanged
		}
	} else {
		if r.Sequence == ^uint64(0) {
			return SelfUpdateStop{}, ErrSelfUpdateStopChanged
		}
		r.Sequence++
		r.Stopped = true
		r.TransactionID = id
		r.ConfigRevision = revision
		r.State = "requested"
		if err = writeControl(d, selfControlCurrent, r); err != nil {
			return SelfUpdateStop{}, err
		}
		if fault != nil {
			if err = fault("stop-current-durable"); err != nil {
				return SelfUpdateStop{}, err
			}
		}
	}
	request := r
	request.State = "requested"
	raw, err := readControlBytes(d, controlRequestName(r), 4096)
	if errors.Is(err, os.ErrNotExist) {
		err = writeControl(d, controlRequestName(r), request)
	} else if err == nil {
		sealed, _ := sealControl(request)
		if !bytes.Equal(raw, sealed) {
			err = ErrSelfUpdateStopJournal
		}
	}
	if err != nil {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	if fault != nil {
		if err = fault("stop-intent-durable"); err != nil {
			return SelfUpdateStop{}, err
		}
	}
	// A repeat also flushes the current record: a previous call may have
	// returned unknown after rename and before successful directory sync.
	if err = writeControl(d, selfControlCurrent, r); err != nil {
		return SelfUpdateStop{}, err
	}
	if err = checkControlRequest(d, r); err != nil {
		return SelfUpdateStop{}, err
	}
	sealed, _ := sealControl(r)
	r, _ = decodeControl(sealed)
	return r, ctx.Err()
}

func CheckSelfUpdateStop(ctx context.Context, path, id string) error {
	if !controlHex(id, 32) {
		return ErrSelfUpdateStopChanged
	}
	r, present, err := ReadSelfUpdateStop(ctx, path)
	if err != nil {
		return err
	}
	if !present {
		return ErrSelfUpdateStopJournal
	}
	if r.Stopped {
		return ErrSelfUpdateStopped
	}
	return nil
}

// begin admits only a bounded Start syscall, never Wait/opkg/payload fsync.
// Stop and actual begin share this control lock. Already admitted trees must
// observe the newer epoch and cancel/join through their exact owner supervisor.
func WithSelfUpdateEffectAdmission(ctx context.Context, path, id string, sequence uint64, effectID string, begin func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !controlHex(id, 32) || sequence == 0 || begin == nil || len(effectID) == 0 || len(effectID) > 64 {
		return ErrSelfUpdateStopChanged
	}
	for _, c := range effectID {
		if c < 'a' || c > 'z' {
			if c < '0' || c > '9' {
				if c != '-' {
					return ErrSelfUpdateStopChanged
				}
			}
		}
	}
	d, err := openControlDirectory(path, false)
	if err != nil {
		return ErrSelfUpdateStopJournal
	}
	defer d.close()
	release, _, err := lockControl(ctx, d)
	if err != nil {
		return err
	}
	defer release()
	r, err := readControlCurrent(d)
	if err != nil || checkControlRequest(d, r) != nil {
		return ErrSelfUpdateStopJournal
	}
	if r.Stopped {
		return ErrSelfUpdateStopped
	}
	if r.Sequence != sequence {
		return ErrSelfUpdateStopChanged
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if d.unchanged() != nil {
		return ErrSelfUpdateStopJournal
	}
	return begin()
}

// Observations do not restore authority. Caller must independently join owned
// work before observation, and must freshly verify again before reporting a
// stopped-success to an operator. A callback is never supplied through HTTP.
func RecordSelfUpdateStopped(ctx context.Context, path, id string, sequence uint64, observe Guard) (SelfUpdateStop, error) {
	if observe == nil || observe(ctx) != nil {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	d, err := openControlDirectory(path, false)
	if err != nil {
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	defer d.close()
	release, _, err := lockControl(ctx, d)
	if err != nil {
		return SelfUpdateStop{}, err
	}
	r, err := readControlCurrent(d)
	if err != nil || checkControlRequest(d, r) != nil {
		release()
		return SelfUpdateStop{}, ErrSelfUpdateStopJournal
	}
	if !r.Stopped || r.TransactionID != id || r.Sequence != sequence {
		release()
		return SelfUpdateStop{}, ErrSelfUpdateStopChanged
	}
	// Persist an unknown observation first. A failed second fresh observer
	// must never leave a newly confirmed stopped record behind.
	r.State = "cleanup-unknown"
	err = writeControl(d, selfControlCurrent, r)
	release()
	if err != nil {
		return SelfUpdateStop{}, err
	}
	if err = observe(ctx); err != nil {
		return SelfUpdateStop{}, err
	}
	release, _, err = lockControl(ctx, d)
	if err != nil {
		return SelfUpdateStop{}, err
	}
	defer release()
	current, err := readControlCurrent(d)
	if err != nil || checkControlRequest(d, current) != nil || current.InstallationID != r.InstallationID || current.Sequence != sequence || current.TransactionID != id || !current.Stopped {
		return SelfUpdateStop{}, ErrSelfUpdateStopChanged
	}
	current.State = "observed-stopped"
	if err = writeControl(d, selfControlCurrent, current); err != nil {
		return SelfUpdateStop{}, err
	}
	sealed, _ := sealControl(current)
	current, _ = decodeControl(sealed)
	return current, ctx.Err()
}
