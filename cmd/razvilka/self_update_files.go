package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func nativeSelfUpdateFileAdapter() app.SelfUpdateFileAdapter {
	if runtime.GOOS != "linux" {
		return nil
	}
	return updatecheck.NewSelfUpdateFileAdapterWithAuthority(selfUpdateStopCheck, selfUpdateEffectAdmission, selfUpdateRuntimeInactive)
}

func selfUpdateStopCheck(ctx context.Context, id string) (bool, error) {
	r, present, err := operationgate.ReadSelfUpdateStop(ctx, selfUpdateDefaultPath("/opt/var/lib/razvilka/self-update-stop"))
	if err != nil {
		return false, err
	}
	if !present {
		return false, operationgate.ErrSelfUpdateStopJournal
	}
	if r.Stopped && r.TransactionID != id {
		return false, operationgate.ErrSelfUpdateStopChanged
	}
	return r.Stopped, nil
}

func selfUpdateEffectAdmission(ctx context.Context, id, installationID string, sequence uint64, action, effect string, begin func() error) error {
	return selfUpdateEffectAdmissionAt(ctx, selfUpdateDefaultPath("/opt/var/lib/razvilka/self-update-stop"), selfUpdateDefaultPath("/opt/etc/razvilka/config.json"), id, installationID, sequence, action, effect, begin)
}

// The production worker supplies its fixed roots above. A bootstrap's offline
// source state is separate from durable Stop; it uses only the original live
// control epoch and never the stopped compensation admission.
func selfUpdateEffectAdmissionAt(ctx context.Context, control, configuration, id, installationID string, sequence uint64, action, effect string, begin func() error) error {
	switch action {
	case "start/live", "stop-owned", "replace-to-rollback", "bootstrap-offline":
	default:
		return operationgate.ErrSelfUpdateStopChanged
	}
	r, present, err := operationgate.ReadSelfUpdateStop(ctx, control)
	if err != nil {
		return err
	}
	if !present {
		return operationgate.ErrSelfUpdateStopJournal
	}
	if !r.Stopped {
		return operationgate.WithSelfUpdateEffectAdmission(ctx, control, id, installationID, sequence, effect, begin)
	}
	if action == "bootstrap-offline" {
		return operationgate.ErrSelfUpdateStopped
	}
	store, err := config.LoadExisting(configuration)
	if err != nil {
		return err
	}
	cfg := store.Get()
	if cfg.SafeMode || cfg.ServiceControl.Stopped {
		return updatecheck.ErrReviewChanged
	}
	return operationgate.WithSelfUpdateStoppedEffectAdmission(ctx, control, id, installationID, sequence, cfg.Revision, action, effect, begin)
}

func selfUpdateAuthorityReview(control string) func(context.Context, string) (updatecheck.SelfUpdateAuthority, error) {
	return func(ctx context.Context, id string) (updatecheck.SelfUpdateAuthority, error) {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id {
			return updatecheck.SelfUpdateAuthority{}, updatecheck.ErrReviewChanged
		}
		r, err := operationgate.InitializeSelfUpdateControl(ctx, control)
		if err != nil {
			return updatecheck.SelfUpdateAuthority{}, err
		}
		return updatecheck.SelfUpdateAuthority{InstallationID: r.InstallationID, Sequence: r.Sequence}, nil
	}
}

// The sole Manager owns adapter aggregation. Missing owner observers refuse;
// neither a previous Deactivate result nor an empty process scan is a proof.
func verifySelfUpdateRuntimeInactive(ctx context.Context, observer dataplane.RuntimeInactivityObserver) error {
	if observer == nil {
		return dataplane.ErrRuntimeInactivity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := observer.VerifyRuntimeInactive(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func selfUpdateRuntimeManager() (*dataplane.Manager, error) {
	manager, err := newDataplaneManager(selfUpdateDefaultPath("/opt/var/lib/razvilka/dataplane"), nil)
	if err != nil {
		return nil, err
	}
	if err := registerScopedDNS(manager, nil); err != nil {
		return nil, err
	}
	// This freshly constructed registry is private to this helper. Require
	// every owner contract before Deactivate can perform any cleanup. This is
	// availability only; the Manager still supplies the sole fresh proof.
	for _, adapter := range manager.Adapters {
		if _, ok := adapter.(dataplane.RuntimeInactivityObserver); !ok {
			return nil, dataplane.ErrRuntimeInactivity
		}
	}
	return manager, nil
}

func selfUpdateRuntimeInactive(ctx context.Context, id string) error {
	if _, err := selfUpdateStopCheck(ctx, id); err != nil {
		return err
	}
	if err := independentSelfUpdateFences(ctx, selfUpdateDefaultPath("/opt/etc/razvilka/config.json"), selfUpdateDefaultPath("/opt/var/lib/razvilka/dataplane")); err != nil {
		return err
	}
	manager, err := selfUpdateRuntimeManager()
	if err != nil {
		return err
	}
	adapter, ok := nativeSelfUpdateFileAdapter().(*updatecheck.SelfUpdateFileAdapter)
	if !ok || bindSelfUpdateInstallerRoles(ctx, manager, adapter, id) != nil {
		return dataplane.ErrRuntimeInactivity
	}
	if err := verifySelfUpdateRuntimeInactive(ctx, manager); err != nil {
		return err
	}
	return independentSelfUpdateFences(ctx, selfUpdateDefaultPath("/opt/etc/razvilka/config.json"), manager.StateRoot)
}

func selfUpdateDefaultPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}

func configuredSelfUpdateFiles(installation, files, helper string, control ...string) (*app.SelfUpdateFiles, error) {
	if len(control) > 1 {
		return nil, errors.New("one fixed control authority root required")
	}
	controlRoot := ""
	if len(control) == 1 {
		controlRoot = control[0]
	}
	defaults := []string{"/opt", "/opt/var/lib/razvilka/self-update-files", "/opt/var/lib/razvilka/self-update", "/opt/var/lib/razvilka/self-update-stop"}
	values := []string{installation, files, helper, controlRoot}
	for i, value := range values {
		if strings.TrimSpace(value) != value {
			return nil, errors.New("self update roots must not contain surrounding whitespace")
		}
		if value == "" {
			value = selfUpdateDefaultPath(defaults[i])
		}
		if !filepath.IsAbs(value) || filepath.Clean(value) == filepath.VolumeName(value)+string(filepath.Separator) {
			return nil, errors.New("self update roots must be explicit absolute non-filesystem-root directories")
		}
		values[i] = filepath.Clean(value)
	}
	for _, mutable := range []string{values[1], values[2]} {
		controlPath, retainedPath := values[3], mutable
		if runtime.GOOS == "windows" {
			controlPath, retainedPath = strings.ToLower(controlPath), strings.ToLower(retainedPath)
		}
		if controlPath == retainedPath || strings.HasPrefix(controlPath, retainedPath+string(filepath.Separator)) || strings.HasPrefix(retainedPath, controlPath+string(filepath.Separator)) {
			return nil, errors.New("control authority must be outside file/helper journal trees")
		}
	}
	u := updatecheck.NewUpdater(app.Version, filepath.Dir(values[2]), updatecheck.Deployment{})
	u.Directory = values[2]
	var adapter app.SelfUpdateFileAdapter
	production := true
	for i := range values {
		production = production && values[i] == selfUpdateDefaultPath(defaults[i])
	}
	if production {
		adapter = nativeSelfUpdateFileAdapter()
	}
	f := &app.SelfUpdateFiles{Installation: values[0], Directory: values[1], ControlRoot: values[3], Helper: u, Adapter: adapter}
	if adapter != nil {
		f.JournalReadGuard = func(ctx context.Context, required int) error {
			if required != updatecheck.SelfUpdateReadVersion {
				return errSelfUpdateJournalState
			}
			return boundedSelfUpdateJournalState(ctx, productionSelfUpdateJournalRoots())
		}
	}
	return f, nil
}

func productionSelfUpdateFiles() (*app.SelfUpdateFiles, error) {
	return configuredSelfUpdateFiles("", "", "")
}

func selfUpdatePendingFromEnv() bool {
	f, err := configuredSelfUpdateFiles(os.Getenv("RAZVILKA_SELF_UPDATE_INSTALLATION"), os.Getenv("RAZVILKA_SELF_UPDATE_FILE_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_HELPER_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE"))
	return err != nil || f.Pending()
}

func runSelfUpdateFileCommand(args []string) int {
	f, err := productionSelfUpdateFiles()
	if err != nil {
		return 3
	}
	if len(args) == 1 && args[0] == "current" {
		r, present, err := f.Current()
		if err != nil {
			fmt.Fprintln(os.Stderr, "self update journal unavailable; preserve retained files")
			return 3
		}
		job := f.Helper.Snapshot()
		return writeCommandJSON(map[string]any{"present": present, "transaction": r, "recovery_required": f.Pending(), "helper_id": job.ID, "helper_state": job.State})
	}
	if len(args) != 3 {
		return 2
	}
	revision, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil || args[0] == "settle-stopped-rollback" && (revision == 0 || strconv.FormatUint(revision, 10) != args[2]) {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	guard := func(c context.Context) error {
		if err := independentSelfUpdateFences(c, selfUpdateDefaultPath("/opt/etc/razvilka/config.json"), selfUpdateDefaultPath("/opt/var/lib/razvilka/dataplane")); err != nil {
			return err
		}
		store, err := config.LoadExisting(selfUpdateDefaultPath("/opt/etc/razvilka/config.json"))
		if err != nil {
			return err
		}
		cfg := store.Get()
		if cfg.Revision != revision || cfg.SafeMode || cfg.ServiceControl.Stopped {
			return updatecheck.ErrReviewChanged
		}
		return c.Err()
	}
	if err := f.Action(ctx, args[1], args[0], revision, guard); err != nil {
		fmt.Fprintln(os.Stderr, "matching self update action refused; preserve journals and prior images")
		return 3
	}
	return 0
}

func runSelfUpdateFileHelper(id string) int {
	f, err := productionSelfUpdateFiles()
	if err != nil || f.Adapter == nil {
		return 3
	}
	guard := func(c context.Context) error {
		return independentSelfUpdateFences(c, selfUpdateDefaultPath("/opt/etc/razvilka/config.json"), selfUpdateDefaultPath("/opt/var/lib/razvilka/dataplane"))
	}
	return updatecheck.RunInstallerHelperWithAuthority(id, func(ctx context.Context, job string) error {
		return f.RunHelper(ctx, job, guard)
	}, selfUpdateStopCheck, selfUpdateEffectAdmission, selfUpdateRuntimeInactive)
}

func runSelfUpdateCommandHelper(id, command string) int {
	if nativeSelfUpdateFileAdapter() == nil {
		return 3
	}
	return updatecheck.RunFileCommandHelperWithAuthority(id, command, selfUpdateStopCheck, selfUpdateEffectAdmission, selfUpdateRuntimeInactive)
}

func runSelfUpdateRuntimeQuiesce(args []string) int {
	return runSelfUpdateRuntimeQuiesceWithJournalRoots(args, productionSelfUpdateJournalRoots())
}

func runSelfUpdateRuntimeQuiesceWithJournalRoots(args []string, journalRoots selfUpdateJournalRoots) int {
	if len(args) != 3 {
		return 2
	}
	revision, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil || strconv.FormatUint(revision, 10) != args[1] {
		return 2
	}
	worker, err := strconv.Atoi(args[2])
	if err != nil || worker <= 1 || strconv.Itoa(worker) != args[2] {
		return 2
	}
	if !allowSelfUpdateJournalCommand(journalRoots) {
		return 3
	}
	adapter, ok := nativeSelfUpdateFileAdapter().(interface {
		RuntimeQuiesceAuthority(context.Context, string, uint64, int) error
	})
	if !ok {
		return 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	// This exact helper/command identity must be proven before any Store or
	// runtime manager is opened. Ordinary bootstrap remains fenced.
	if adapter.RuntimeQuiesceAuthority(ctx, args[0], revision, worker) != nil {
		return 3
	}
	if independentSelfUpdateFences(ctx, selfUpdateDefaultPath("/opt/etc/razvilka/config.json"), selfUpdateDefaultPath("/opt/var/lib/razvilka/dataplane")) != nil {
		return 3
	}
	manager, err := selfUpdateRuntimeManager()
	if err != nil {
		return 3
	}
	installer, ok := adapter.(*updatecheck.SelfUpdateFileAdapter)
	if !ok || bindSelfUpdateInstallerRoles(ctx, manager, installer, args[0]) != nil {
		return 3
	}
	if _, err := manager.Deactivate(ctx); err != nil {
		return 3
	}
	if verifySelfUpdateRuntimeInactive(ctx, manager) != nil || adapter.RuntimeQuiesceAuthority(ctx, args[0], revision, worker) != nil {
		return 3
	}
	if independentSelfUpdateFences(ctx, selfUpdateDefaultPath("/opt/etc/razvilka/config.json"), manager.StateRoot) != nil {
		return 3
	}
	return 0
}

// Idle private restore records are canonical checksummed metadata. This reader
// accepts only idle (never recovers prepared/committed images); no record data
// is logged or supplied to the installer. A normal boot later validates scope
// through the owning Coordinator before it opens normal Stores.
func independentSelfUpdateFences(ctx context.Context, configPath, dataplaneRoot string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, generation := range []string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1"} {
		path := filepath.Join(filepath.Dir(configPath), generation)
		root, err := ownedfs.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		data, err := root.ReadLimited("restore.private.json", 12<<20)
		if errors.Is(err, os.ErrNotExist) {
			root.Close()
			continue
		}
		info, statErr := root.Stat("restore.private.json")
		root.Close()
		if err != nil || statErr != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return errors.New("independent private restore inspection unavailable")
		}
		var doc struct {
			Kind    string            `json:"kind"`
			Schema  int               `json:"schema"`
			Scope   string            `json:"scope"`
			ID      string            `json:"id"`
			State   string            `json:"state"`
			Records []json.RawMessage `json:"records"`
			Digest  string            `json:"digest"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return errors.New("independent private restore journal invalid")
		}
		canonical, _ := json.Marshal(doc)
		if !bytes.Equal(data, canonical) || doc.Kind != "razvilka-private-restore" || doc.Schema != 1 || doc.State != "idle" || doc.ID != "" || len(doc.Records) != 0 {
			return errors.New("independent private restore remains fenced")
		}
		scope, err := hex.DecodeString(doc.Scope)
		if err != nil || len(scope) != 32 || hex.EncodeToString(scope) != doc.Scope {
			return errors.New("independent private restore scope invalid")
		}
		wanted := doc.Digest
		doc.Digest = ""
		unsigned, _ := json.Marshal(doc)
		sum := sha256.Sum256(unsigned)
		if hex.EncodeToString(sum[:]) != wanted {
			return errors.New("independent private restore checksum invalid")
		}
	}
	return dataplane.New(dataplaneRoot).CheckExecutionRecovery(ctx)
}

func selfUpdateRecoveryApp(f *app.SelfUpdateFiles, configPath, tokenPath, credentialsPath string, manager *components.Manager, dataplaneRoot string) (*app.App, error) {
	store, err := config.LoadExisting(configPath)
	if err != nil {
		return nil, err
	}
	root, err := ownedfs.Open(filepath.Dir(tokenPath))
	if err != nil {
		return nil, err
	}
	token, err := root.ReadLimited(filepath.Base(tokenPath), 4096)
	root.Close()
	if err != nil {
		return nil, err
	}
	gate, err := security.NewGate(string(token))
	if err != nil {
		return nil, err
	}
	// ConfigureCredentials reads only; do not generate accounts or token files
	// while the six-file installation transaction is unresolved.
	credentialRoot, err := ownedfs.Open(filepath.Dir(credentialsPath))
	if err != nil {
		return nil, err
	}
	_, err = credentialRoot.ReadLimited(filepath.Base(credentialsPath), 64<<10)
	credentialRoot.Close()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := gate.ConfigureCredentials(credentialsPath); err != nil {
		return nil, err
	}
	f.RecoveryGuard = func(c context.Context) error { return independentSelfUpdateFences(c, configPath, dataplaneRoot) }
	a := &app.App{Store: store, Security: gate, Components: manager, SelfUpdate: f.Helper, SelfUpdateFiles: f, Start: time.Now()}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		return nil, err
	}
	if err := independentSelfUpdateFences(context.Background(), configPath, dataplaneRoot); err != nil {
		if errors.Is(err, dataplane.ErrExecutionJournal) {
			a.Operations.FenceJournal()
		} else {
			a.Operations.Fence()
		}
	}
	return a, nil
}

func serveSelfUpdateRecovery(a *app.App, listen string) error {
	if listen == "" {
		listen = a.Store.Get().Listen
	}
	a.EffectiveListen = listen
	handler, err := selfUpdateRecoveryHandler(a)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	cancel()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func selfUpdateRecoveryHandler(a *app.App) (http.Handler, error) {
	sub, err := fs.Sub(embedded, "web")
	if err != nil {
		return nil, err
	}
	core := a.Handler(http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			switch r.URL.Path {
			case "/api/v1/auth/status", "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/self-update/current", "/api/v1/self-update/recovery", "/api/v1/components/recovery", "/api/v1/status", "/api/v1/service-control/runtime":
			default:
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "self update recovery required", http.StatusServiceUnavailable)
				return
			}
		}
		core.ServeHTTP(w, r)
	}), nil
}
