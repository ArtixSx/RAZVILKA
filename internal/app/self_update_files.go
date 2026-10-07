package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

var errSelfUpdateRecovery = errors.New("self update requires matching file/helper recovery")
var selfUpdateID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// SelfUpdateFileAdapter binds fixed installer effects to the reviewed helper
// job and real process evidence. Run accepts only the fixed command names below.
// A historical command without supervision proof must fail Quiescence/Observe.
// Method signatures use neutral primitives and the OPS-owned journal File type;
// an implementation in updatecheck must never import app.
type SelfUpdateFileAdapter interface {
	Inspect(context.Context, string) error
	Ready(context.Context, string) error
	Review(context.Context, string) (revision uint64, migratedConfigSHA256 string, files []selfupdatejournal.File, err error)
	Authority(context.Context, string, uint64) error
	AuthorityAction(context.Context, string, uint64, string) error
	EffectAdmission(context.Context, string, string, string, func() error) error
	Quiescence(context.Context, string) error
	Run(context.Context, string, string) error
	Observe(context.Context, string, string) error
	Live(context.Context, string, bool) error
	Startup(context.Context, string, int) error
	Finish(context.Context, string, bool) error
}

// RunHelper is a new handoff only, never a crash-resume command. Each external
// command has a distinct durable intent and is supervised by the trusted OPS
// provider. A failed command remains unknown; only a failed live check after a
// confirmed command may enter the separate rollback sequence.
func (f *SelfUpdateFiles) RunHelper(ctx context.Context, id string, guard selfupdatejournal.Check) error {
	if f == nil || f.Adapter == nil || guard == nil || !selfUpdateID.MatchString(id) {
		return errSelfUpdateRecovery
	}
	if r, present, err := f.Current(); err != nil {
		return err
	} else if present && (r.Pending() || r.ID == id) {
		return selfupdatejournal.ErrPending
	} else if present {
		if err := f.Adapter.Inspect(ctx, r.ID); err != nil {
			return err
		}
	}
	revision, _, _, err := f.Adapter.Review(ctx, id)
	if err != nil {
		return err
	}
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "install", "start-candidate-panel"} {
		if err := f.Action(ctx, id, action, revision, guard); err != nil {
			return err
		}
	}
	if err := f.Action(ctx, id, "accept-live", revision, guard); err == nil {
		return nil
	} else {
		// Acceptance may have succeeded but final helper settlement failed.
		// Never roll back an accepted transaction because its receipt is late.
		r, present, readErr := f.Current()
		if readErr != nil || !present || r.ID != id || r.Phase != "command-finished" || r.Command != "start-candidate-panel" {
			return errors.Join(err, readErr)
		}
		for _, action := range []string{"stop-candidate-panel", "restore", "restore-private-state", "start-rollback-panel", "accept-rollback"} {
			if rollbackErr := f.Action(ctx, id, action, revision, guard); rollbackErr != nil {
				return errors.Join(err, rollbackErr)
			}
		}
		return err // Rolled back is an unsuccessful upgrade, even after true acceptance.
	}
}

// SelfUpdateFiles opens pre-existing roots on each observation/action. Changing
// config location never relocates a retained production journal implicitly.
type SelfUpdateFiles struct {
	Installation string
	Directory    string
	// Fixed trusted startup root, independent of all application/private images.
	ControlRoot string
	Adapter     SelfUpdateFileAdapter
	// Helper is the read-only retained helper receipt reader. Its directory is
	// explicit and independent of configuration/dataplane location overrides.
	Helper *updatecheck.Updater
	// RecoveryGuard reads independent private/network journals. It must never
	// recover or mutate them as a side effect of application file repair.
	RecoveryGuard selfupdatejournal.Check
	// Trusted fixed-deployment reader check. It preserves the provider's
	// original callback context and grants no process or control effects.
	JournalReadGuard func(context.Context, int) error
}

func (f *SelfUpdateFiles) Current() (selfupdatejournal.Receipt, bool, error) {
	if f == nil {
		return selfupdatejournal.Receipt{}, false, nil
	}
	if !filepath.IsAbs(f.Directory) {
		return selfupdatejournal.Receipt{}, false, errSelfUpdateRecovery
	}
	if _, err := os.Lstat(f.Directory); errors.Is(err, os.ErrNotExist) {
		return selfupdatejournal.Receipt{}, false, nil
	}
	s, err := selfupdatejournal.Open(f.Installation, f.Directory)
	if err != nil {
		return selfupdatejournal.Receipt{}, false, err
	}
	defer s.Close()
	r, present, err := s.Current()
	if err == nil && !present {
		err = f.checkEmptyJournal()
	}
	return r, present, err
}

// A crash before current publication can retain preparation images. Missing
// current must not conceal those orphans or an unsafe writer marker.
func (f *SelfUpdateFiles) checkEmptyJournal() error {
	before, err := os.Lstat(f.Directory)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(f.Directory)
	if err != nil {
		return err
	}
	defer root.Close()
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return selfupdatejournal.ErrMismatch
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := directory.Readdirnames(2)
	directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if len(names) == 0 {
		return nil
	}
	if len(names) != 1 || names[0] != ".writer.lock" {
		return errors.New("unreferenced self update preparation requires review")
	}
	owned, err := ownedfs.Open(f.Directory)
	if err != nil {
		return err
	}
	defer owned.Close()
	marker, err := owned.ReadLimited(".writer.lock", 64)
	info, statErr := owned.Stat(".writer.lock")
	if err != nil || statErr != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 || string(marker) != "RAZVILKA self update writer v1\n" {
		return errors.New("self update writer marker unavailable")
	}
	return nil
}

func (f *SelfUpdateFiles) Ready(ctx context.Context, id string) error {
	if f == nil || f.Adapter == nil || !selfUpdateID.MatchString(id) {
		return errSelfUpdateRecovery
	}
	if err := f.controlAuthority(ctx, true); err != nil {
		return err
	}
	r, present, err := f.Current()
	if err != nil {
		return err
	}
	if present && r.Pending() || f.Helper != nil && f.Helper.StartupPending() {
		return selfupdatejournal.ErrPending
	}
	if present {
		if err := f.Adapter.Inspect(ctx, r.ID); err != nil {
			return err
		}
	}
	if f.RecoveryGuard != nil {
		if err := f.RecoveryGuard(ctx); err != nil {
			return err
		}
	}
	if err := f.Adapter.Ready(ctx, id); err != nil {
		return err
	}
	if f.RecoveryGuard != nil {
		return f.RecoveryGuard(ctx)
	}
	return ctx.Err()
}

func (f *SelfUpdateFiles) Pending() bool {
	if f == nil {
		return false
	}
	if f.controlPending() {
		return true
	}
	r, present, err := f.Current()
	if err != nil || present && r.Pending() || f.Helper != nil && f.Helper.StartupPending() {
		return true
	}
	if present {
		// Terminal receipts retain both images. A parser-only success cannot
		// authorize ordinary startup when those images or installed files are
		// unverified. Inspect is bounded, read-only and never resumes a command.
		if f.Adapter == nil {
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return f.Adapter.Inspect(ctx, r.ID) != nil || ctx.Err() != nil
	}
	return false
}

func (f *SelfUpdateFiles) Action(ctx context.Context, id, action string, revision uint64, guard selfupdatejournal.Check) error {
	if f == nil || f.Adapter == nil || guard == nil || !selfUpdateID.MatchString(id) || !selfUpdateFileAction(action) {
		return errSelfUpdateRecovery
	}
	if action == "settle-stopped-rollback" {
		return f.settleStoppedRollback(ctx, id, revision, guard)
	}
	reviewRevision, migratedSHA, files, err := f.Adapter.Review(ctx, id)
	if err != nil {
		return err
	}
	if reviewRevision != revision {
		return selfupdatejournal.ErrMismatch
	}
	authority := func(c context.Context) error {
		if err := f.controlAction(c, id, revision, action); err != nil {
			return err
		}
		if err := guard(c); err != nil {
			return err
		}
		if f.RecoveryGuard != nil {
			if err := f.RecoveryGuard(c); err != nil {
				return err
			}
		}
		return f.Adapter.AuthorityAction(c, id, revision, selfUpdateActionAuthority(action))
	}
	quiescence := func(c context.Context) error { return f.Adapter.Quiescence(c, id) }
	if err := authority(ctx); err != nil {
		return err
	}
	if action == "prepare" {
		if previous, present, err := f.Current(); err != nil {
			return err
		} else if present {
			if previous.Pending() {
				return selfupdatejournal.ErrPending
			}
			if err := f.Adapter.Inspect(ctx, previous.ID); err != nil {
				return err
			}
		}
		wanted := map[string]bool{"bin/razvilka": false, "etc/init.d/S99razvilka": false, "etc/razvilka/config.json": false, "etc/razvilka/service-catalog.json": false, "etc/razvilka/community-catalog.json": false, "etc/razvilka/sources.json": false}
		for _, file := range files {
			seen, allowed := wanted[file.Target]
			if !allowed || seen || file.Target == "etc/razvilka/config.json" && (file.SHA256 != migratedSHA || len(migratedSHA) != 64) {
				return errors.New("exact six-file installation with staged migrated configuration digest required before Prepare")
			}
			wanted[file.Target] = true
		}
		if len(files) != len(wanted) {
			return errors.New("complete six-file installation required before Prepare")
		}
		if f.ControlRoot != "" {
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, f.ControlRoot); err != nil {
				return err
			}
		}
		// Create only the fixed journal child of an already-owned parent. Do
		// not repair an existing unsafe directory or delete retained images.
		parent, err := ownedfs.Open(filepath.Dir(f.Directory))
		if err != nil {
			return err
		}
		if err = parent.MkdirAll(filepath.Base(f.Directory), 0700); err == nil && runtime.GOOS != "windows" {
			err = parent.Sync()
		}
		parent.Close()
		if err != nil {
			return err
		}
	}
	s, err := selfupdatejournal.Open(f.Installation, f.Directory)
	if err != nil {
		return err
	}
	defer s.Close()
	switch action {
	case "prepare":
		return s.Prepare(ctx, id, files, authority, quiescence)
	case "install":
		r, present, err := s.Current()
		if err != nil || !present || r.ID != id {
			return errors.Join(selfupdatejournal.ErrMismatch, err)
		}
		if r.Rollback || !selfUpdatePreFilesComplete(r.Commands) || r.Phase != "prepared" && r.Phase != "installing" {
			return selfupdatejournal.ErrPending
		}
		return s.InstallAdmitted(ctx, id, authority, quiescence, func(c context.Context, effect string, begin func() error) error {
			return f.Adapter.EffectAdmission(c, id, "start/live", effect, begin)
		})
	case "restore":
		r, present, err := s.Current()
		if err != nil || !present || r.ID != id {
			return errors.Join(selfupdatejournal.ErrMismatch, err)
		}
		knownInactive := selfUpdatePreFilesComplete(r.Commands) && (r.Phase == "prepared" || r.Phase == "installing" || r.Phase == "installed") || r.Phase == "command-finished" && r.Command == "stop-candidate-panel"
		if !r.Rollback && !knownInactive {
			return selfupdatejournal.ErrPending
		}
		return s.RestoreAdmitted(ctx, id, authority, quiescence, func(c context.Context, effect string, begin func() error) error {
			return f.Adapter.EffectAdmission(c, id, "replace-to-rollback", effect, begin)
		})
	case "accept-live", "accept-rollback":
		rollback := action == "accept-rollback"
		r, present, err := s.Current()
		if err != nil {
			return err
		}
		if !present || r.ID != id {
			return selfupdatejournal.ErrMismatch
		}
		terminal := r.Phase == "accepted" && !rollback || r.Phase == "rolled-back" && rollback
		if terminal {
			// Only helper-receipt settlement may be retried. No command or file
			// replacement is replayed; the provider must verify retained images,
			// installed files and fresh independent live proof in Finish.
			if f.Helper == nil || !f.Helper.StartupPending() || f.Helper.Snapshot().ID != id {
				return selfupdatejournal.ErrPending
			}
		} else {
			command := "start-candidate-panel"
			if rollback {
				command = "start-rollback-panel"
			}
			if r.Phase != "command-finished" || r.Command != command {
				return selfupdatejournal.ErrPending
			}
			if err := s.Accept(ctx, id, rollback, authority, func(c context.Context) error { return f.Adapter.Live(c, id, rollback) }); err != nil {
				return err
			}
		}
		if err := authority(ctx); err != nil {
			return err
		}
		return f.Adapter.Finish(ctx, id, rollback)
	case "resolve-unknown":
		r, present, err := s.Current()
		if err != nil {
			return err
		}
		if !present || r.ID != id {
			return selfupdatejournal.ErrMismatch
		}
		return s.ResolveUnknown(ctx, id, authority, quiescence, func(c context.Context) error { return f.Adapter.Observe(c, id, r.Command) })
	case "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel":
		r, present, err := s.Current()
		if err != nil || !present || r.ID != id {
			return errors.Join(selfupdatejournal.ErrMismatch, err)
		}
		if r.Phase == "command-started" {
			return selfupdatejournal.ErrUnknown
		}
		allowed := action == "stop-old-panel" && !r.Rollback && r.Phase == "prepared" && len(r.Commands) == 0 ||
			action == "prepare-private-state" && !r.Rollback && r.Phase == "prepared" && slices.Equal(r.Commands, []string{"stop-old-panel"}) ||
			action == "quiesce-old-runtime" && !r.Rollback && r.Phase == "prepared" && slices.Equal(r.Commands, []string{"stop-old-panel", "prepare-private-state"}) ||
			action == "start-candidate-panel" && !r.Rollback && r.Phase == "installed" && selfUpdatePreFilesComplete(r.Commands) ||
			action == "stop-candidate-panel" && !r.Rollback && r.Phase == "command-finished" && r.Command == "start-candidate-panel" ||
			action == "restore-private-state" && r.Rollback && r.Phase == "restored" ||
			action == "start-rollback-panel" && r.Rollback && r.Phase == "command-finished" && r.Command == "restore-private-state"
		if !allowed {
			return selfupdatejournal.ErrPending
		}
		if err := s.Execute(ctx, id, action, authority, func(c context.Context) error { return f.Adapter.Run(c, id, action) }); err != nil {
			return err
		}
		return authority(ctx)
	default:
		return errors.New("unsupported self update file action")
	}
}

func selfUpdatePreFilesComplete(commands []string) bool {
	return slices.Equal(commands, []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"})
}

func selfUpdateActionAuthority(action string) string {
	switch action {
	case "stop-old-panel", "stop-candidate-panel", "quiesce-old-runtime":
		return "stop-owned"
	case "restore", "restore-private-state", "settle-stopped-rollback":
		return "replace-to-rollback"
	case "resolve-unknown":
		return "read/observe"
	default:
		return "start/live"
	}
}

type selfUpdateFileAdmissionKey struct{}
type selfUpdateFileAdmission struct {
	id      string
	inspect bool
	action  string
}

func (a *App) PendingSelfUpdateRecovery() bool {
	if a.SelfUpdateFiles == nil {
		return false
	}
	if a.SelfUpdateFiles.Pending() {
		return true
	}
	return a.SelfUpdate != nil && a.SelfUpdate.StartupPending()
}

func (a *App) selfUpdateFileGuard(ctx context.Context) error {
	if err := a.SelfUpdateFiles.controlAuthority(ctx, true); err != nil {
		if scope, ok := ctx.Value(selfUpdateFileAdmissionKey{}).(selfUpdateFileAdmission); ok && scope.inspect {
			return nil
		}
		scope, ok := ctx.Value(selfUpdateFileAdmissionKey{}).(selfUpdateFileAdmission)
		if !ok || a.Store == nil || !selfUpdateFileAction(scope.action) || a.SelfUpdateFiles.controlAction(ctx, scope.id, a.Store.Get().Revision, scope.action) != nil {
			return errSelfUpdateRecovery
		}
	}
	if !a.PendingSelfUpdateRecovery() {
		return nil
	}
	if scope, ok := ctx.Value(componentAdmissionKey{}).(componentAdmission); ok && scope.stop {
		return nil
	}
	if scope, ok := ctx.Value(selfUpdateFileAdmissionKey{}).(selfUpdateFileAdmission); ok {
		if scope.inspect {
			return nil
		}
		r, present, err := a.SelfUpdateFiles.Current()
		if err == nil && scope.id != "" && present && scope.id == r.ID {
			return nil
		}
		// A retained helper interrupted before Prepare still needs matching
		// admission. The trusted provider must prove supervision before effects.
		if err == nil && !present && a.SelfUpdateFiles.Helper != nil && a.SelfUpdateFiles.Helper.Snapshot().ID == scope.id {
			return nil
		}
	}
	return errSelfUpdateRecovery
}

func (a *App) selfUpdateStartupAllowed(ctx context.Context, jobID string, helperPID int) error {
	if a.SelfUpdateFiles == nil {
		return nil
	} // Legacy test fixtures have no file protocol.
	return a.SelfUpdateFiles.StartupAllowed(ctx, jobID, helperPID)
}

func (f *SelfUpdateFiles) StartupAllowed(ctx context.Context, jobID string, helperPID int) error {
	if f == nil {
		return errSelfUpdateRecovery
	}
	if err := f.controlAuthority(ctx, false); err != nil {
		return err
	}
	r, present, err := f.Current()
	if err != nil || !present || !r.Pending() || r.ID != jobID || helperPID <= 1 || f.Adapter == nil {
		return errSelfUpdateRecovery
	}
	if r.Phase != "command-started" && r.Phase != "command-finished" {
		return errSelfUpdateRecovery
	}
	if r.Command != "start-candidate-panel" && r.Command != "start-rollback-panel" {
		return errSelfUpdateRecovery
	}
	if f.RecoveryGuard != nil {
		if err := f.RecoveryGuard(ctx); err != nil {
			return err
		}
	}
	return f.Adapter.Startup(ctx, jobID, helperPID)
}
