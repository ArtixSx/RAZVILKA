//go:build linux

package nativeowner

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
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/usquediag"
	"golang.org/x/sys/unix"
)

const (
	usqueRegistrationStateFile = "usque-initial-registration.private.json"
	usqueRegistrationLockFile  = "usque-initial-registration.lock"
	usqueRegistrationOutput    = "usque-registration-output.private"
	usqueRegistrationLimit     = cloudflareprovider.MaxImportBytes
)

type usqueRegistrationState struct {
	Schema         int    `json:"schema"`
	InstallationID string `json:"installation_id"`
	BinarySHA256   string `json:"binary_sha256"`
	AttemptID      string `json:"attempt_id"`
	SessionSHA256  string `json:"session_sha256,omitempty"`
	Session        []byte `json:"session,omitempty"`
}

// Issued by the original command owner only when its provider child never
// started. A nonzero exit, cancellation after Start, or uncertain cleanup
// does not return this capability.
var errUSQUERegistrationNoChild = errors.New("USQUE provider child never started")

// PrepareUSQUEInitial runs only the pinned consumer registration command.
// It never starts a proxy, changes routes or uses an existing account token.
// A private attempt is reserved before the command. A missing final result
// after reservation is treated as an unknown provider outcome and is not retried.
func PrepareUSQUEInitial(ctx context.Context, gate *operationgate.Gate, binding USQUERegistrationBinding) (USQUERegistrationResult, error) {
	if !usquediag.OwnedUSQUENativeBinaryAudited(binding.BinarySHA256, runtime.GOARCH) {
		return USQUERegistrationResult{}, ErrUSQUERegistrationUnsupported
	}
	var binary *heldFile
	defer func() { _ = binary.close() }()
	return prepareUSQUEInitial(ctx, gate, binding, func(ctx context.Context) error {
		var err error
		binary, err = openHeld(ctx, binding.Binary, binding.BinarySHA256, 64<<20, false, true)
		if err != nil {
			return ErrUSQUERegistrationUnsupported
		}
		return nil
	}, func(ctx context.Context, root *ownedfs.Root, review func(context.Context) error, epoch *operationgate.ControlEpochReview) ([]byte, error) {
		return runUSQUERegistration(ctx, root, binary, review, epoch.WithStart)
	})
}

type usqueRegistrar func(context.Context, *ownedfs.Root, func(context.Context) error, *operationgate.ControlEpochReview) ([]byte, error)

func prepareUSQUEInitial(ctx context.Context, gate *operationgate.Gate, binding USQUERegistrationBinding, prepare func(context.Context) error, register usqueRegistrar) (result USQUERegistrationResult, err error) {
	if ctx == nil || gate == nil || !binding.AcceptTOS || binding.Configs == nil || binding.Review == nil {
		return result, ErrUSQUERegistrationConsent
	}
	if _, finite := ctx.Deadline(); !finite {
		return result, ErrUSQUERegistrationChanged
	}
	err = gate.WithExclusiveContext(ctx, func() error {
		epoch, err := gate.ReviewControlEpoch(ctx, binding.ControlRoot)
		if err != nil {
			return ErrUSQUERegistrationChanged
		}
		defer epoch.Close()
		review := func(c context.Context) error {
			if c.Err() != nil || epoch.Current(c) != nil || binding.Review(c) != nil || epoch.Current(c) != nil {
				return ErrUSQUERegistrationChanged
			}
			return nil
		}
		if err := review(ctx); err != nil {
			return err
		}
		root, current, closeRoot, err := openUSQUERegistrationRoot(binding.ControlRoot)
		if err != nil {
			return err
		}
		defer closeRoot()
		check := func(c context.Context) error { return errors.Join(review(c), current()) }
		result, err = prepareUSQUERegistrationState(ctx, root, binding, epoch, current, check, prepare, register)
		return err
	})
	if err != nil {
		if errors.Is(err, operationgate.ErrBusy) || ctx.Err() != nil {
			err = errors.Join(ErrUSQUERegistrationChanged, err)
		}
		return USQUERegistrationResult{}, err
	}
	return result, nil
}

func openUSQUERegistrationRoot(path string) (*ownedfs.Root, func() error, func(), error) {
	if protectedPath(path, true) != nil {
		return nil, nil, nil, ErrUSQUERegistrationState
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, nil, nil, ErrUSQUERegistrationState
	}
	lock, err := root.OpenFile(usqueRegistrationLockFile, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		_ = root.Close()
		return nil, nil, nil, ErrUSQUERegistrationState
	}
	closeRoot := func() { _ = lock.Close(); _ = root.Close() }
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		closeRoot()
		return nil, nil, nil, ErrUSQUERegistrationBusy
	}
	current := func() error {
		actual, rootErr := os.Lstat(path)
		anchored, heldErr := root.RootInfo()
		file, fileErr := lock.Stat()
		named, namedErr := root.Stat(usqueRegistrationLockFile)
		if rootErr != nil || heldErr != nil || fileErr != nil || namedErr != nil || protectedPath(path, true) != nil ||
			!os.SameFile(actual, anchored) || !privateUSQUERegistrationFile(file) || !privateUSQUERegistrationFile(named) || !os.SameFile(file, named) {
			return ErrUSQUERegistrationState
		}
		return nil
	}
	if err := current(); err != nil {
		closeRoot()
		return nil, nil, nil, err
	}
	return root, current, closeRoot, nil
}

func privateUSQUERegistrationFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

func prepareUSQUERegistrationState(ctx context.Context, root *ownedfs.Root, binding USQUERegistrationBinding, epoch *operationgate.ControlEpochReview, current func() error, check, prepare func(context.Context) error, register usqueRegistrar) (USQUERegistrationResult, error) {
	installation := epoch.Reference().InstallationID
	state, exists, err := readUSQUERegistrationState(root, installation, binding.BinarySHA256)
	if err != nil {
		return USQUERegistrationResult{}, err
	}
	defer func() { clear(state.Session) }()
	slot, err := binding.Configs.ReadExpert("usque", "main")
	if err != nil {
		return USQUERegistrationResult{}, ErrUSQUERegistrationSlot
	}
	if exists && len(state.Session) != 0 {
		return stageUSQUERegistration(ctx, binding, check, state, slot, true)
	}
	if slot.Source != "missing" {
		return USQUERegistrationResult{}, ErrUSQUERegistrationSlot
	}
	if exists {
		return USQUERegistrationResult{}, ErrUSQUERegistrationPending
	}
	if err := prepare(ctx); err != nil {
		return USQUERegistrationResult{}, err
	}
	if err := check(ctx); err != nil {
		return USQUERegistrationResult{}, err
	}
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	state = usqueRegistrationState{Schema: 1, InstallationID: installation, BinarySHA256: binding.BinarySHA256, AttemptID: hex.EncodeToString(nonce[:])}
	if err := writeUSQUERegistrationState(root, state); err != nil {
		return USQUERegistrationResult{}, err
	}
	state.Session, err = register(ctx, root, check, epoch)
	if err != nil {
		if err == errUSQUERegistrationNoChild {
			if err := discardUnstartedUSQUERegistration(root, state, current); err != nil {
				return USQUERegistrationResult{}, errors.Join(ErrUSQUERegistrationPending, err)
			}
			return USQUERegistrationResult{}, errors.Join(ErrUSQUERegistrationChanged, ctx.Err())
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return USQUERegistrationResult{}, errors.Join(ErrUSQUERegistrationPending, ErrUSQUERegistrationTimeout)
		}
		return USQUERegistrationResult{}, errors.Join(ErrUSQUERegistrationPending, ctx.Err())
	}
	if !validUSQUERegistrationSession(state.Session, binding.BinarySHA256) {
		return USQUERegistrationResult{}, errors.Join(ErrUSQUERegistrationPending, ErrUSQUERegistrationSession)
	}
	state.SessionSHA256 = usqueRegistrationDigest(state.Session)
	// Settlement is a private durable fact. Keep a known, joined result even
	// when consent/scope changed before it can go into the engine slot.
	if err := writeUSQUERegistrationState(root, state); err != nil {
		return USQUERegistrationResult{}, errors.Join(ErrUSQUERegistrationPending, err)
	}
	return stageUSQUERegistration(ctx, binding, check, state, slot, false)
}

func discardUnstartedUSQUERegistration(root *ownedfs.Root, reserved usqueRegistrationState, current func() error) error {
	if len(reserved.Session) != 0 || reserved.SessionSHA256 != "" || current() != nil {
		return ErrUSQUERegistrationState
	}
	state, exists, err := readUSQUERegistrationState(root, reserved.InstallationID, reserved.BinarySHA256)
	defer clear(state.Session)
	// The same installation directory and original writer lock are still
	// held. Neither another nonce nor a committed result may be removed.
	if err != nil || !exists || state.AttemptID != reserved.AttemptID || len(state.Session) != 0 || current() != nil ||
		root.Remove(usqueRegistrationStateFile) != nil || root.Sync() != nil || current() != nil {
		return ErrUSQUERegistrationState
	}
	return nil
}

func stageUSQUERegistration(ctx context.Context, binding USQUERegistrationBinding, check func(context.Context) error, state usqueRegistrationState, slot engineconfig.Content, reused bool) (USQUERegistrationResult, error) {
	if err := check(ctx); err != nil {
		return USQUERegistrationResult{}, err
	}
	if slot.Source == "staged" && slot.SHA256 == state.SessionSHA256 {
		return USQUERegistrationResult{SHA256: state.SessionSHA256, Reused: true}, nil
	}
	if slot.Source != "missing" {
		return USQUERegistrationResult{}, ErrUSQUERegistrationSlot
	}
	staged, err := binding.Configs.StageIfMissing(ctx, "usque", "main", string(state.Session))
	if errors.Is(err, restorejournal.ErrConflict) {
		return USQUERegistrationResult{}, ErrUSQUERegistrationSlot
	}
	if err != nil || staged.SHA256 != state.SessionSHA256 {
		return USQUERegistrationResult{}, ErrUSQUERegistrationState
	}
	if err := check(ctx); err != nil {
		return USQUERegistrationResult{}, err
	}
	return USQUERegistrationResult{SHA256: staged.SHA256, Reused: reused}, nil
}

func readUSQUERegistrationState(root *ownedfs.Root, installation, binarySHA string) (usqueRegistrationState, bool, error) {
	var state usqueRegistrationState
	file, err := root.OpenFile(usqueRegistrationStateFile, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, ErrUSQUERegistrationState
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !privateUSQUERegistrationFile(info) {
		return state, false, ErrUSQUERegistrationState
	}
	raw, err := io.ReadAll(io.LimitReader(file, usqueRegistrationLimit*2+1))
	defer clear(raw)
	after, statErr := file.Stat()
	named, namedErr := root.Stat(usqueRegistrationStateFile)
	checked := heldFile{info: info, private: true}
	if err != nil || statErr != nil || namedErr != nil || !checked.sameMetadata(after) || !checked.sameMetadata(named) || len(raw) > usqueRegistrationLimit*2 ||
		int64(len(raw)) != info.Size() || json.Unmarshal(raw, &state) != nil || state.Schema != 1 || state.InstallationID != installation || state.BinarySHA256 != binarySHA || !hexShape(state.AttemptID, 32) ||
		(len(state.Session) == 0 && state.SessionSHA256 != "") || (len(state.Session) != 0 && (state.SessionSHA256 != usqueRegistrationDigest(state.Session) || !validUSQUERegistrationSession(state.Session, binarySHA))) {
		clear(state.Session)
		return usqueRegistrationState{}, false, ErrUSQUERegistrationState
	}
	canonical, err := json.Marshal(state)
	defer clear(canonical)
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(state.Session)
		return usqueRegistrationState{}, false, ErrUSQUERegistrationState
	}
	return state, true, nil
}

func writeUSQUERegistrationState(root *ownedfs.Root, state usqueRegistrationState) error {
	raw, err := json.Marshal(state)
	defer clear(raw)
	if err != nil || root.WriteAtomic(usqueRegistrationStateFile, raw, 0o600) != nil || root.Sync() != nil {
		return ErrUSQUERegistrationState
	}
	return nil
}

func usqueRegistrationDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validUSQUERegistrationSession(raw []byte, binarySHA string) bool {
	if len(raw) == 0 || len(raw) > usqueRegistrationLimit {
		return false
	}
	parsed, err := cloudflareprovider.ParseImport(cloudflareprovider.SourceUSQUE, raw)
	if err != nil || parsed.Preview().Format != "usque-v1" {
		return false
	}
	_, quic := usquediag.ValidateOwnedUSQUENativeAssets(raw, "QUIC", binarySHA, runtime.GOARCH)
	_, h2 := usquediag.ValidateOwnedUSQUENativeAssets(raw, "HTTP/2", binarySHA, runtime.GOARCH)
	return quic == nil && h2 == nil
}

func runUSQUERegistration(parent context.Context, root *ownedfs.Root, binary *heldFile, review func(context.Context) error, start func(context.Context, func() error) error) (result []byte, resultErr error) {
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	file, err := root.OpenFile(usqueRegistrationOutput, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrUSQUERegistrationState
	}
	defer func() {
		held, heldErr := file.Stat()
		named, namedErr := root.Stat(usqueRegistrationOutput)
		if heldErr != nil || namedErr != nil || !os.SameFile(held, named) || root.Remove(usqueRegistrationOutput) != nil {
			resultErr = errors.Join(resultErr, ErrUSQUERegistrationState)
		}
		if file.Close() != nil {
			resultErr = errors.Join(resultErr, ErrUSQUERegistrationState)
		}
		if resultErr != nil {
			clear(result)
			result = nil
		}
	}()
	if binary.current(ctx) != nil || review(ctx) != nil {
		return nil, errUSQUERegistrationNoChild
	}
	// The upstream writes by os.Create. The supplied FD names the already
	// created 0600 file, so neither a path swap nor the daemon umask can
	// redirect or expose the keys when the child truncates and writes it.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "--config", "/proc/self/fd/4", "register", "--accept-tos", "--name", "RAZVILKA")
	cmd.Args[0] = binary.path
	cmd.ExtraFiles = []*os.File{binary.file, file}
	cmd.Env = []string{"LANG=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 2 * time.Second
	// Only actual Start is linearized with the durable Stop epoch; Wait and
	// readback happen outside that short lock. The one pinned child is joined
	// even if control changes immediately after Start. Its output is discarded.
	startErr := start(ctx, func() error {
		if err := binary.metadataCurrent(ctx); err != nil {
			return err
		}
		return cmd.Start()
	})
	if cmd.Process == nil {
		return nil, errUSQUERegistrationNoChild
	}
	if startErr != nil {
		cancel()
	}
	if waitErr := cmd.Wait(); startErr != nil || waitErr != nil {
		return nil, errors.Join(ErrUSQUERegistrationPending, ctx.Err())
	}
	settlement, finish := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer finish()
	info, statErr := file.Stat()
	if statErr != nil || !privateUSQUERegistrationFile(info) || info.Size() > usqueRegistrationLimit || binary.current(settlement) != nil {
		return nil, ErrUSQUERegistrationPending
	}
	raw, err := io.ReadAll(io.NewSectionReader(file, 0, usqueRegistrationLimit+1))
	if err != nil || len(raw) > usqueRegistrationLimit || int64(len(raw)) != info.Size() || settlement.Err() != nil {
		clear(raw)
		return nil, ErrUSQUERegistrationPending
	}
	return raw, nil
}
