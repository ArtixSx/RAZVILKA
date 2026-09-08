package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/nativeenrollment"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var (
	ErrEnrollmentPending       = errors.New("WARP registration has an unresolved local checkpoint; no new registration was sent")
	ErrEnrollmentStore         = errors.New("WARP private enrollment state is unavailable or invalid")
	ErrLegacyGeneratorRequired = errors.New("existing wgcf account requires wgcf to rebuild its profile; explicitly create a new account to use the built-in generator")
)

const nativePending = "pending.json"
const nativeCurrent = "current.json"

// The canonical image is one leased atomic checkpoint and restore target.
// Legacy directories remain immutable migration inputs. No state selects a
// live runtime: completing registration only stages an engine profile.
type nativeEnrollment struct {
	Schema    int       `json:"schema"`
	Directory string    `json:"directory"`
	CreatedAt time.Time `json:"created_at"`
	Fresh     bool      `json:"fresh"`
}

func (m *Manager) nativeRootPath() string { return filepath.Join(m.Root, "native-enrollment") }
func (m *Manager) hasNativeStateLocked() bool {
	for _, path := range []string{filepath.Join(m.Root, nativeenrollment.FileName), filepath.Join(m.nativeRootPath(), nativePending), filepath.Join(m.nativeRootPath(), nativeCurrent)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}
func readNativeEnrollment(d nativeenrollment.Document, name string) (nativeEnrollment, bool, error) {
	if !d.Has(name) {
		return nativeEnrollment{}, false, nil
	}
	var e nativeEnrollment
	if json.Unmarshal(d.Get(name), &e) != nil || e.Schema != 1 || e.CreatedAt.IsZero() || e.CreatedAt.After(time.Now().Add(time.Minute)) || !nativeenrollment.ValidDirectory(e.Directory) {
		return e, false, ErrEnrollmentStore
	}
	return e, true, nil
}
func (m *Manager) nativeStatusLocked(ctx context.Context, status *Status) {
	status.RegistrationState = "none"
	if status.AccountRegistered {
		status.RegistrationState = "legacy-wgcf"
	}
	if !m.hasNativeStateLocked() {
		return
	}
	image, err := nativeenrollment.ReadEffective(ctx, m.Root)
	if err != nil {
		status.RegistrationState = "local-state-invalid"
		return
	}
	d, err := nativeenrollment.Decode(image)
	if err != nil {
		status.RegistrationState = "local-state-invalid"
		return
	}
	pending, exists, err := readNativeEnrollment(d, nativePending)
	if err != nil {
		status.RegistrationState = "local-state-invalid"
		return
	}
	if exists {
		status.RegistrationState = "pending-review"
		status.RecoveryAvailable = d.Has(pending.Directory+"/response.private.json") || d.Has(pending.Directory+"/registration.private.json")
	}
	current, present, err := readNativeEnrollment(d, nativeCurrent)
	if err != nil {
		status.RegistrationState = "local-state-invalid"
		return
	}
	if !present {
		return
	}
	profile, err := m.nativeProfileLocked(ctx, d, current)
	defer eraseNative(profile)
	if err != nil {
		status.RegistrationState = "local-state-invalid"
		return
	}
	status.AccountRegistered = true
	if !exists {
		status.RegistrationState = "registered"
	}
}

func (m *Manager) generateNativeLocked(ctx context.Context, acceptTOS, fresh bool) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	target, err := nativeenrollment.Open(m.Root)
	if err != nil {
		return Result{}, ErrEnrollmentStore
	}
	defer target.Close()
	image, err := target.Read(ctx)
	if err != nil {
		return Result{}, ErrEnrollmentStore
	}
	d, err := nativeenrollment.Decode(image)
	if err != nil {
		return Result{}, ErrEnrollmentStore
	}
	saveContext := func(saveCtx context.Context) error {
		after, err := target.Save(saveCtx, image, d)
		if err == nil {
			image = after
		}
		return err
	}
	save := func() error { return saveContext(ctx) }
	pending, exists, err := readNativeEnrollment(d, nativePending)
	if err != nil {
		return Result{}, ErrEnrollmentStore
	}
	if exists {
		if err := m.recoverNativeLocked(ctx, &d, pending); err != nil {
			return Result{}, ErrEnrollmentPending
		}
		if err := save(); err != nil {
			return Result{}, ErrEnrollmentPending
		}
		return m.stageNativeLocked(ctx, &d, pending, true, save)
	}
	current, exists, err := readNativeEnrollment(d, nativeCurrent)
	if err != nil {
		return Result{}, ErrEnrollmentStore
	}
	if exists && !fresh {
		// Copy-only migration under the same lease. Old checkpoints stay untouched.
		if err := save(); err != nil {
			return Result{}, ErrEnrollmentStore
		}
		return m.stageNativeLocked(ctx, &d, current, false, save)
	}
	if !acceptTOS {
		return Result{}, ErrTermsAcceptanceRequired
	}
	// Reserve the bounded response/derived registration before the one POST.
	// Reaching capacity must not discard the last recoverable response.
	if len(image.Data) > nativeenrollment.MaxBytes-(512<<10) || len(d.Files) > nativeenrollment.MaxFiles-4 {
		return Result{}, ErrEnrollmentStore
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Result{}, ErrEnrollmentStore
	}
	pending = nativeEnrollment{Schema: 1, Directory: "attempt-" + hex.EncodeToString(nonce[:]), CreatedAt: time.Now().UTC(), Fresh: fresh}
	encoded, _ := json.Marshal(pending)
	d.Set(nativePending, encoded)
	// Durable intent before generating key or sending exactly one POST. The
	// cross-process image lease excludes generation, restore and recovery writers.
	if err := save(); err != nil {
		return Result{}, ErrEnrollmentPending
	}
	checkpoint := func(name string, data []byte) error {
		if d.Has(pending.Directory + "/" + name) {
			return ErrEnrollmentStore
		}
		d.Set(pending.Directory+"/"+name, data)
		if name == "response.private.json" {
			checkpointCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			return saveContext(checkpointCtx)
		}
		return save()
	}
	api := m.nativeAPI(func(response []byte) error { return checkpoint("response.private.json", response) })
	registrar := cloudflareprovider.Registrar{API: api, CheckpointKey: func(key []byte) error { return checkpoint("private-key.bin", key) }}
	candidate, err := registrar.NewCandidate(ctx, true)
	if err != nil {
		return Result{}, errors.Join(ErrEnrollmentPending, err)
	}
	if err := storeNativeCandidate(&d, pending, candidate); err != nil {
		return Result{}, ErrEnrollmentPending
	}
	if err := save(); err != nil {
		return Result{}, ErrEnrollmentPending
	}
	return m.stageNativeLocked(ctx, &d, pending, true, save)
}
func storeNativeCandidate(d *nativeenrollment.Document, e nativeEnrollment, candidate cloudflareprovider.RegistrationCandidate) error {
	var out bytes.Buffer
	if err := candidate.WritePrivateSnapshot(&out); err != nil {
		return ErrEnrollmentStore
	}
	defer eraseNative(out.Bytes())
	d.Set(e.Directory+"/registration.private.json", out.Bytes())
	return nil
}
func (m *Manager) recoverNativeLocked(ctx context.Context, d *nativeenrollment.Document, e nativeEnrollment) error {
	if profile, err := m.nativeProfileLocked(ctx, *d, e); err == nil {
		eraseNative(profile)
		return nil
	}
	key, response := d.Get(e.Directory+"/private-key.bin"), d.Get(e.Directory+"/response.private.json")
	defer eraseNative(key)
	defer eraseNative(response)
	candidate, err := cloudflareprovider.RecoverConsumerCandidate(key, response, e.CreatedAt)
	if err != nil {
		return ErrEnrollmentStore
	}
	return storeNativeCandidate(d, e, candidate)
}
func (m *Manager) nativeProfileLocked(ctx context.Context, d nativeenrollment.Document, e nativeEnrollment) ([]byte, error) {
	raw := d.Get(e.Directory + "/registration.private.json")
	if raw == nil {
		var err error
		raw, err = cloudflareprovider.LegacyRegistrationSnapshot(d.Get(e.Directory + "/provider/accounts.private.json"))
		if err != nil {
			return nil, ErrEnrollmentStore
		}
	}
	defer eraseNative(raw)
	var profile bytes.Buffer
	err := cloudflareprovider.WithRegistrationCandidate(ctx, raw, func(_ context.Context, c cloudflareprovider.WireGuardCandidate) error { return c.WriteConfig(&profile) })
	if err != nil || ValidateProfile(profile.Bytes()) != nil {
		eraseNative(profile.Bytes())
		return nil, ErrEnrollmentStore
	}
	return profile.Bytes(), nil
}
func (m *Manager) stageNativeLocked(ctx context.Context, d *nativeenrollment.Document, e nativeEnrollment, completing bool, save func() error) (Result, error) {
	profile, err := m.nativeProfileLocked(ctx, *d, e)
	if err != nil {
		return Result{}, err
	}
	defer eraseNative(profile)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if _, err := m.EngineConfigs.Stage("warp-wg", "main", string(profile)); err != nil {
		return Result{}, errors.New("WARP candidate could not be staged; saved enrollment was retained")
	}
	if completing {
		if e.Fresh {
			if err := m.recordRotationLocked(); err != nil {
				return Result{}, err
			}
		}
		encoded, _ := json.Marshal(e)
		d.Set(nativeCurrent, encoded)
		d.Delete(nativePending)
		if err := save(); err != nil {
			return Result{}, ErrEnrollmentStore
		}
	}
	return Result{OK: true, Source: "native-cloudflare", FreshAccount: completing && e.Fresh, SHA256: digest(profile), Message: "Профиль сохранён как черновик. Регистрация не подтверждает работу туннеля: выполните безопасную проверку, затем примените профиль."}, nil
}
func eraseNative(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// NativeRestore holds the live Manager mutex and the exact canonical file lease
// through journal commit/cache handover. No network method is available here.
type NativeRestore struct {
	*nativeenrollment.Target
	manager *Manager
}

func (s *NativeRestore) Close() error {
	if s.manager == nil {
		return nil
	}
	err := s.Target.Close()
	s.manager.mu.Unlock()
	s.manager = nil
	return err
}
func (m *Manager) BeginNativeRestore(ctx context.Context) (*NativeRestore, error) {
	if !m.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	target, err := nativeenrollment.Open(m.Root)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	return &NativeRestore{Target: target, manager: m}, nil
}
func (m *Manager) ExportNativePrivateIfPresent(ctx context.Context) (*nativeenrollment.Snapshot, error) {
	if !m.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	defer m.mu.Unlock()
	if !m.hasNativeStateLocked() {
		return nil, nil
	}
	target, err := nativeenrollment.Open(m.Root)
	if err != nil {
		return nil, ErrEnrollmentStore
	}
	defer target.Close()
	image, err := target.Read(ctx)
	if err != nil {
		return nil, ErrEnrollmentStore
	}
	d, err := nativeenrollment.Decode(image)
	if err != nil {
		return nil, ErrEnrollmentStore
	}
	snapshot, err := nativeenrollment.SnapshotOf(d)
	if err != nil {
		return nil, ErrEnrollmentStore
	}
	return &snapshot, nil
}
