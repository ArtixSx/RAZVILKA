package updatecheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const updaterOwner = "razvilka-self-update-v1"
const productionUpdateRoot = "/opt/var/lib/razvilka/self-update"

var ErrBusy = errors.New("self-update-busy")
var ErrReviewChanged = errors.New("self-update-review-changed")
var ErrHandoffUncertain = errors.New("self-update-handoff-uncertain")
var jobIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Deployment struct {
	Paths      map[string]string `json:"paths"`
	Executable string            `json:"executable"`
	Port       string            `json:"port"`
}

type Job struct {
	ID             string    `json:"id,omitempty"`
	State          string    `json:"state"`
	Stage          string    `json:"stage"`
	Message        string    `json:"message"`
	Code           string    `json:"code,omitempty"`
	Release        *Release  `json:"release,omitempty"`
	Downloaded     int64     `json:"downloaded_bytes"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
	CanApply       bool      `json:"can_apply"`
	CanCancel      bool      `json:"can_cancel"`
	ReviewToken    string    `json:"review_token,omitempty"`
	ConfigRevision uint64    `json:"config_revision"`
	Verification   string    `json:"verification"`
	Attestation    bool      `json:"attestation_verified"`
	HelperPID      int       `json:"helper_pid,omitempty"`
}

type updateRecord struct {
	Owner             string            `json:"owner"`
	Job               Job               `json:"job"`
	CurrentVersion    string            `json:"current_version"`
	ExecutableHash    string            `json:"executable_hash"`
	ConfigFingerprint string            `json:"config_fingerprint"`
	Files             map[string]string `json:"files"`
	ParentPID         int               `json:"parent_pid"`
	Deployment        Deployment        `json:"deployment"`
}

type Updater struct {
	Current       string
	Directory     string
	Deployment    Deployment
	Client        *http.Client
	mu            sync.Mutex
	record        updateRecord
	cancel        context.CancelFunc
	done          chan struct{}
	handoffDone   chan struct{}
	handoffActive bool
	parent        context.Context
	// Tests inject bounded local preflight and launch behavior. Browser input
	// never configures a command, URL, destination or transport.
	eligibility func(Deployment) error
	preflight   func(context.Context, string, Release) error
	launch      func(string) (int, error)
	space       func(string, int64) error
	persistHook func(updateRecord) error
	alive       func(int) bool
}

func NewUpdater(current, stateRoot string, deployment Deployment) *Updater {
	return &Updater{Current: current, Directory: filepath.Join(stateRoot, "self-update"), Deployment: deployment, Client: OfficialClient(3 * time.Minute), parent: context.Background(), eligibility: CheckDeployment, preflight: preflightInstaller, launch: launchInstallerHelper, space: checkUpdateSpace, alive: helperAlive}
}

func (u *Updater) Start(ctx context.Context) { u.mu.Lock(); u.parent = ctx; u.mu.Unlock() }

// RetainHandoff keeps the request's exclusive admission while the independent
// helper stops this process. A refused helper releases it without a restart.
func (u *Updater) RetainHandoff(release func()) {
	u.mu.Lock()
	parent := u.parent
	helperPID := u.record.Job.HelperPID
	u.handoffActive = true
	done := make(chan struct{})
	u.handoffDone = done
	u.mu.Unlock()
	go func() {
		defer close(done)
		defer func() { u.mu.Lock(); u.handoffActive = false; u.mu.Unlock() }()
		defer release() // Joined cleanup still owns installation admission.
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-parent.Done():
				return
			case <-timer.C:
				job := u.Snapshot()
				terminal := job.State == "completed" || job.State == "rolled-back" || job.State == "failed"
				if terminal && (helperPID <= 1 || !u.alive(helperPID)) {
					return
				}
			}
		}
	}()
}

// StartupPending is checked before HTTP/background writers start. A new
// daemon may perform its own boot recovery, but the installer's snapshot must
// remain authoritative until healthcheck commits or rolls back the upgrade.
func (u *Updater) StartupPending() bool {
	job := u.Snapshot()
	return job.State == "installing" || job.State == "restarting" || job.State == "requires-review"
}
func (u *Updater) InstallationLocked() bool { u.mu.Lock(); defer u.mu.Unlock(); return u.handoffActive }

func (u *Updater) Snapshot() Job {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readHelperStatusLocked()
	job := u.record.Job
	if job.State == "" {
		job = Job{State: "idle", Stage: "idle", Message: "Обновление приложения не запускалось.", Verification: "github-release-sha256"}
	}
	return cloneJob(job)
}

func cloneJob(job Job) Job {
	if job.Release != nil {
		release := *job.Release
		job.Release = &release
	}
	return job
}

func (u *Updater) readHelperStatusLocked() {
	if u.cancel != nil {
		return
	}
	root, err := ownedfs.Open(u.Directory)
	if err != nil {
		if u.record.Job.ID != "" {
			u.invalidateRecordLocked()
		}
		return
	}
	defer root.Close()
	data, err := root.ReadLimited("current.json", 64<<10)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) || u.record.Job.ID != "" {
			u.invalidateRecordLocked()
		}
		return
	}
	var record updateRecord
	if json.Unmarshal(data, &record) != nil || record.Owner != updaterOwner || !jobIDPattern.MatchString(record.Job.ID) {
		u.invalidateRecordLocked()
		return
	}
	if record.Job.State == "ready" && (record.Job.Release == nil || record.Job.Release.ID <= 0 || record.Job.ReviewToken == "" || len(record.Files) != 9 || record.ConfigFingerprint == "") {
		u.invalidateRecordLocked()
		return
	}
	if u.record.Job.ID != "" && u.record.Job.ID != record.Job.ID {
		u.invalidateRecordLocked()
		return
	}
	if (record.Job.State == "installing" || record.Job.State == "restarting") && record.Job.HelperPID > 1 && !u.alive(record.Job.HelperPID) {
		record.Job.State = "requires-review"
		record.Job.Code = "helper-interrupted"
		record.Job.Message = "Обновление прервано. Проверьте установленную версию и состояние отката."
		record.Job.CanApply = false
	}
	if record.Job.State == "installing" && record.Job.HelperPID <= 1 && time.Since(record.Job.UpdatedAt) > 10*time.Second {
		record.Job.State = "requires-review"
		record.Job.Code = "handoff-interrupted"
		record.Job.Message = "Передача установщику прервана. Проверьте результат перед повторным обновлением."
		record.Job.CanApply = false
		record.Job.CanCancel = false
	}
	if record.ParentPID != os.Getpid() && (record.Job.State == "ready" || record.Job.State == "preparing") {
		record.Job.State = "interrupted"
		record.Job.CanApply = false
		record.Job.CanCancel = false
		record.Job.ReviewToken = ""
		record.Job.Message = "После перезапуска подготовьте обновление заново."
	}
	u.record = record
}

func (u *Updater) invalidateRecordLocked() {
	u.record.Job.State = "requires-review"
	u.record.Job.CanApply = false
	u.record.Job.CanCancel = false
	u.record.Job.ReviewToken = ""
	u.record.Job.Code = "update-record-invalid"
	u.record.Job.Message = "Журнал обновления повреждён. Установка приостановлена до проверки."
}

func (u *Updater) Prepare(revision uint64, fingerprint string) (Job, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readHelperStatusLocked()
	if u.cancel != nil || u.record.Job.State == "installing" || u.record.Job.State == "restarting" || u.record.Job.State == "requires-review" {
		return cloneJob(u.record.Job), ErrBusy
	}
	if err := u.eligibility(u.Deployment); err != nil {
		u.record = updateRecord{Job: Job{State: "blocked", Stage: "preflight", Code: err.Error(), Message: updateMessage(err.Error()), Verification: "github-release-sha256"}}
		return cloneJob(u.record.Job), nil
	}
	// Keep at most one prepared archive. Delete only the previous recorded
	// random job after its worker has joined and no installation is active.
	if jobIDPattern.MatchString(u.record.Job.ID) {
		root, err := ownedfs.Open(u.Directory)
		if err != nil {
			return Job{}, err
		}
		err = root.RemoveAll(u.record.Job.ID)
		root.Close()
		if err != nil {
			return Job{}, err
		}
	}
	var random [16]byte
	_, _ = rand.Read(random[:])
	id := hex.EncodeToString(random[:])
	now := time.Now().UTC()
	u.record = updateRecord{Owner: updaterOwner, Job: Job{ID: id, State: "preparing", Stage: "metadata", Message: "Проверяем официальный релиз.", StartedAt: now, UpdatedAt: now, CanCancel: true, ConfigRevision: revision, Verification: "github-release-sha256"}, CurrentVersion: u.Current, ConfigFingerprint: fingerprint, ParentPID: os.Getpid(), Deployment: u.Deployment}
	if err := u.createRootLocked(); err != nil {
		return Job{}, err
	}
	if err := u.persistLocked(); err != nil {
		return Job{}, err
	}
	ctx, cancel := context.WithTimeout(u.parent, 8*time.Minute)
	u.cancel = cancel
	u.done = make(chan struct{})
	go u.prepare(ctx, id, u.done)
	return cloneJob(u.record.Job), nil
}

func (u *Updater) createRootLocked() error {
	parent, err := ownedfs.Open(filepath.Dir(u.Directory))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.MkdirAll(filepath.Base(u.Directory), 0700)
}

func (u *Updater) persistLocked() error {
	if u.persistHook != nil {
		return u.persistHook(u.record)
	}
	root, err := ownedfs.Open(u.Directory)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := json.Marshal(u.record)
	if err != nil {
		return err
	}
	return root.WriteAtomic("current.json", data, 0600)
}

func (u *Updater) progress(id, stage, message string, bytes int64) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.record.Job.ID != id {
		return ErrReviewChanged
	}
	job := &u.record.Job
	job.Stage = stage
	job.Message = message
	job.Downloaded = bytes
	job.UpdatedAt = time.Now().UTC()
	return u.persistLocked()
}

func (u *Updater) prepare(ctx context.Context, id string, done chan struct{}) {
	var failure error
	defer func() {
		if ctx.Err() != nil {
			failure = ctx.Err()
		}
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.record.Job.ID == id {
			job := &u.record.Job
			job.CanCancel = false
			job.UpdatedAt = time.Now().UTC()
			if failure != nil {
				job.State = "failed"
				job.Code = safeUpdateCode(failure)
				job.Message = updateMessage(job.Code)
				job.CanApply = false
				job.ReviewToken = ""
				if errors.Is(failure, context.Canceled) {
					job.State = "cancelled"
				} else if errors.Is(failure, context.DeadlineExceeded) {
					job.Code = "prepare-timeout"
				}
			}
			_ = u.persistLocked()
		}
		if u.cancel != nil {
			u.cancel()
			u.cancel = nil
		}
		close(done)
	}()
	release, err := FetchRelease(ctx, u.Client, u.Current, runtime.GOARCH, 0)
	if err != nil {
		failure = err
		return
	}
	u.mu.Lock()
	u.record.Job.Release = &release
	u.mu.Unlock()
	if err = u.space(u.Directory, release.Archive.Size); err != nil {
		failure = err
		return
	}
	root, err := ownedfs.Open(u.Directory)
	if err != nil {
		failure = err
		return
	}
	defer root.Close()
	if err = root.MkdirAll(id, 0700); err != nil {
		failure = err
		return
	}
	jobRoot, err := ownedfs.Open(filepath.Join(u.Directory, id))
	if err != nil {
		failure = err
		return
	}
	defer jobRoot.Close()
	if err = u.progress(id, "downloading", "Скачиваем официальный пакет.", 0); err != nil {
		failure = err
		return
	}
	lastProgress := time.Time{}
	err = Download(ctx, u.Client, release.Archive, jobRoot, "release.tar.gz", func(total int64) {
		if time.Since(lastProgress) > time.Second {
			lastProgress = time.Now()
			_ = u.progress(id, "downloading", "Скачиваем официальный пакет.", total)
		}
	})
	if err != nil {
		failure = err
		return
	}
	if err = u.progress(id, "verifying", "Проверяем файлы и совместимость роутера.", release.Archive.Size); err != nil {
		failure = err
		return
	}
	files, err := ExtractInstallFiles(ctx, jobRoot, "release.tar.gz", release)
	if err != nil {
		failure = err
		return
	}
	if err = u.eligibility(u.Deployment); err != nil {
		failure = err
		return
	}
	if err = VerifyExtracted(jobRoot, files, release); err != nil {
		failure = err
		return
	}
	if err = u.progress(id, "preflight", "Проверяем возможность установки без изменения настроек.", release.Archive.Size); err != nil {
		failure = err
		return
	}
	if err = u.preflight(ctx, filepath.Join(u.Directory, id, "bundle"), release); err != nil {
		failure = err
		return
	}
	executableHash, err := hashRegularFile(u.Deployment.Executable, MaximumBinaryBytes)
	if err != nil {
		failure = err
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if ctx.Err() != nil {
		failure = ctx.Err()
		return
	}
	var token [32]byte
	_, _ = rand.Read(token[:])
	u.record.ExecutableHash = executableHash
	u.record.Files = files
	u.record.Job.State = "ready"
	u.record.Job.Stage = "ready"
	u.record.Job.Message = "Пакет проверен. Можно установить обновление."
	u.record.Job.CanApply = true
	u.record.Job.ReviewToken = hex.EncodeToString(token[:])
}

func (u *Updater) Cancel() (Job, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cancel == nil {
		return cloneJob(u.record.Job), ErrBusy
	}
	u.cancel()
	u.record.Job.Message = "Останавливаем подготовку…"
	u.record.Job.CanApply = false
	return cloneJob(u.record.Job), nil
}

func (u *Updater) Wait(ctx context.Context) error {
	u.mu.Lock()
	jobs := []chan struct{}{u.done, u.handoffDone}
	if u.cancel != nil {
		u.cancel()
	}
	u.mu.Unlock()
	for _, done := range jobs {
		if done == nil {
			continue
		}
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (u *Updater) Apply(ctx context.Context, id, token string, revision uint64, fingerprint string) (Job, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readHelperStatusLocked()
	r := &u.record
	if u.cancel != nil || r.Job.State != "ready" || !r.Job.CanApply {
		return cloneJob(r.Job), ErrBusy
	}
	if r.Job.ID != id || r.Job.ReviewToken != token || token == "" || r.Job.ConfigRevision != revision || r.ConfigFingerprint != fingerprint || r.ParentPID != os.Getpid() || time.Since(r.Job.UpdatedAt) > 15*time.Minute {
		return cloneJob(r.Job), ErrReviewChanged
	}
	if err := u.eligibility(u.Deployment); err != nil {
		return cloneJob(r.Job), err
	}
	release, err := FetchRelease(ctx, u.Client, u.Current, runtime.GOARCH, r.Job.Release.ID)
	if err != nil || !reflect.DeepEqual(release, *r.Job.Release) {
		return cloneJob(r.Job), ErrReviewChanged
	}
	root, err := ownedfs.Open(filepath.Join(u.Directory, id))
	if err != nil {
		return cloneJob(r.Job), err
	}
	defer root.Close()
	if err = VerifyExtracted(root, r.Files, release); err != nil {
		return cloneJob(r.Job), err
	}
	actual, err := hashRegularFile(u.Deployment.Executable, MaximumBinaryBytes)
	if err != nil || actual != r.ExecutableHash {
		return cloneJob(r.Job), ErrReviewChanged
	}
	r.Job.State = "installing"
	r.Job.Stage = "handoff"
	r.Job.CanApply = false
	r.Job.CanCancel = false
	r.Job.ReviewToken = ""
	r.Job.Message = "Обновление запускается. Панель ненадолго перезапустится."
	r.Job.UpdatedAt = time.Now().UTC()
	if err = u.persistLocked(); err != nil {
		return cloneJob(r.Job), err
	}
	pid, err := u.launch(id)
	if err != nil {
		r.Job.State = "failed"
		r.Job.Code = "helper-launch-failed"
		r.Job.Message = updateMessage(r.Job.Code)
		_ = u.persistLocked()
		return cloneJob(r.Job), err
	}
	r.Job.HelperPID = pid
	if err = u.persistLocked(); err != nil {
		r.Job.Code = "helper-handoff-uncertain"
		r.Job.Message = "Запрос передан установщику. Проверяем результат запуска…"
		return cloneJob(r.Job), ErrHandoffUncertain
	}
	return cloneJob(r.Job), nil
}

func safeUpdateCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "prepare-cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "prepare-timeout"
	}
	code := err.Error()
	if len(code) < 80 && regexp.MustCompile(`^[a-z][a-z0-9-]+$`).MatchString(code) {
		return code
	}
	return "update-verification-failed"
}

func updateMessage(code string) string {
	switch code {
	case "production-layout-required":
		return "Эта тестовая или нестандартная установка не обновляется автоматически. Основная версия роутера сохранена."
	case "root-required", "unsupported-platform":
		return "Для установки нужна штатная служба RAZVILKA на роутере."
	case "production-path-ownership-refused":
		return "Автообновление недоступно: права или владелец папок установки не прошли проверку. Требуется проверка прав на роутере. Текущая версия сохранена."
	case "release-not-an-upgrade":
		return "Более нового подходящего стабильного релиза пока нет. Текущая сборка сохранена."
	case "insufficient-update-space":
		return "Недостаточно свободного места для пакета и резервной копии."
	case "helper-launch-failed":
		return "Не удалось запустить обновление. Установленная версия не заменена."
	default:
		return "Подготовка обновления остановлена: проверка не пройдена. Установленная версия сохранена."
	}
}
