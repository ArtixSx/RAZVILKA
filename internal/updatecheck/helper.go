package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// RunInstallerHelper is an internal command of the currently trusted binary.
// It accepts only a random job identifier from a root-owned reviewed record;
// neither script text nor installation paths are accepted on the command line.
func RunInstallerHelper(id string) int {
	if !jobIDPattern.MatchString(id) || checkRootOwnedPath(productionUpdateRoot) != nil {
		return 2
	}
	root, err := ownedfs.Open(productionUpdateRoot)
	if err != nil {
		return 2
	}
	defer root.Close()
	var record updateRecord
	for attempt := 0; attempt < 30; attempt++ {
		data, err := root.ReadLimited("current.json", 64<<10)
		if err != nil || json.Unmarshal(data, &record) != nil {
			return 2
		}
		if record.Owner != updaterOwner || record.Job.ID != id || record.Job.State != "installing" || record.Job.Release == nil || record.ParentPID <= 1 || record.Job.ReviewToken != "" {
			return 2
		}
		if record.Job.HelperPID == os.Getpid() {
			break
		}
		if attempt == 29 {
			return 2
		}
		time.Sleep(100 * time.Millisecond)
	}
	finish := func(state, code, message string) int {
		record.Job.State = state
		record.Job.Stage = state
		record.Job.Code = code
		record.Job.Message = message
		record.Job.CanApply = false
		record.Job.CanCancel = false
		record.Job.UpdatedAt = time.Now().UTC()
		data, _ := json.Marshal(record)
		if root.WriteAtomic("current.json", data, 0600) != nil {
			return 3
		}
		if state == "completed" {
			return 0
		}
		return 3
	}
	if checkDeploymentLayout(record.Deployment) != nil || checkProductionPID(record.ParentPID, record.Deployment.Executable) != nil {
		return finish("failed", "deployment-changed", "Обновление отменено: изменилась установка приложения.")
	}
	actual, err := hashRegularFile(record.Deployment.Executable, MaximumBinaryBytes)
	if err != nil || actual != record.ExecutableHash {
		return finish("failed", "running-binary-changed", "Обновление отменено: текущий файл приложения изменился.")
	}
	if !helperConfigMatches(record) {
		return finish("failed", "settings-changed", "Настройки изменились. Подготовьте обновление заново.")
	}
	jobRoot, err := ownedfs.Open(filepath.Join(productionUpdateRoot, id))
	if err != nil {
		return finish("failed", "prepared-files-unavailable", "Не найдены подготовленные файлы.")
	}
	defer jobRoot.Close()
	if VerifyExtracted(jobRoot, record.Files, *record.Job.Release) != nil {
		return finish("failed", "prepared-files-changed", "Файлы изменились после проверки. Обновление отменено.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	err = preflightInstaller(ctx, filepath.Join(productionUpdateRoot, id, "bundle"), *record.Job.Release)
	cancel()
	if err != nil {
		return finish("failed", "installer-preflight-refused", "Повторная проверка установки не пройдена. Текущая версия сохранена.")
	}
	if !helperConfigMatches(record) || VerifyExtracted(jobRoot, record.Files, *record.Job.Release) != nil || checkProductionPID(record.ParentPID, record.Deployment.Executable) != nil {
		return finish("failed", "review-changed", "Настройки или подготовленные файлы изменились. Подготовьте обновление заново.")
	}
	// HTTP received the accepted job before the old daemon is stopped. No API
	// cancellation is accepted after this point; the installer owns rollback.
	record.Job.Stage = "restarting"
	record.Job.State = "restarting"
	record.Job.Message = "Устанавливаем проверенный пакет и перезапускаем панель."
	record.Job.UpdatedAt = time.Now().UTC()
	if data, _ := json.Marshal(record); root.WriteAtomic("current.json", data, 0600) != nil {
		return 3
	}
	output, err := jobRoot.OpenFile("installer.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "installer-log-unavailable", "Не удалось подготовить журнал. Версия не заменена.")
	}
	defer output.Close()
	command := exec.Command("/bin/sh", filepath.Join(productionUpdateRoot, id, "bundle/scripts/upgrade-entware.sh"), "--apply", "--without-components")
	command.Env = commandEnvironment()
	command.Stdin = nil
	bounded := &limitedLog{writer: output, remaining: 512 << 10}
	command.Stdout = bounded
	command.Stderr = bounded
	if err := runTransactionalInstaller(command, 20*time.Minute); err != nil {
		if errors.Is(err, errInstallerTimeout) {
			return finish("requires-review", "installer-timeout", "Установка превысила время ожидания. Проверьте состояние приложения и отката.")
		}
		// Do not infer a successful rollback from the installer's nonzero exit.
		// Report restored only when the old executable is present and its own
		// healthcheck confirms the exact supervised process and dataplane.
		oldHash, hashErr := hashRegularFile(record.Deployment.Executable, MaximumBinaryBytes)
		if hashErr == nil && oldHash == record.ExecutableHash && confirmInstalledHealth(record.CurrentVersion) {
			return finish("rolled-back", "upgrade-rolled-back", "Обновление не прошло проверку. Предыдущая версия восстановлена и отвечает.")
		}
		return finish("requires-review", "upgrade-needs-review", "Установка не подтверждена. Проверьте приложение и сохранённую резервную копию.")
	}
	if !confirmInstalledHealth(record.Job.Release.Version) {
		return finish("requires-review", "new-version-not-confirmed", "Установщик завершился, но новая версия не подтвердила готовность.")
	}
	return finish("completed", "", "Обновление установлено. Панель готова к работе.")
}

type limitedLog struct {
	mu        sync.Mutex
	writer    io.Writer
	remaining int64
}

func (l *limitedLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := len(data)
	if l.remaining > 0 {
		n := min(int64(size), l.remaining)
		if _, err := l.writer.Write(data[:n]); err != nil {
			return 0, err
		}
		l.remaining -= n
	}
	return size, nil
}

func confirmInstalledHealth(expectedVersion string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	version := exec.CommandContext(ctx, "/opt/bin/razvilka", "-version")
	configureBoundedCommand(version)
	version.Env = commandEnvironment()
	out := &cappedOutput{maximum: 1024}
	version.Stdout = out
	version.Stderr = io.Discard
	if runBoundedCommand(version) != nil || strings.TrimSpace(out.String()) != expectedVersion {
		return false
	}
	pid := exec.CommandContext(ctx, "/bin/sh", "/opt/etc/init.d/S99razvilka", "pid")
	configureBoundedCommand(pid)
	pid.Env = commandEnvironment()
	out = &cappedOutput{maximum: 128}
	pid.Stdout = out
	pid.Stderr = io.Discard
	if runBoundedCommand(pid) != nil {
		return false
	}
	id := strings.TrimSpace(out.String())
	if id == "" || strings.Trim(id, "0123456789") != "" {
		return false
	}
	lan := exec.CommandContext(ctx, "/bin/sh", "/opt/etc/init.d/S99razvilka", "lan-ip")
	configureBoundedCommand(lan)
	lan.Env = commandEnvironment()
	out = &cappedOutput{maximum: 128}
	lan.Stdout = out
	lan.Stderr = io.Discard
	if runBoundedCommand(lan) != nil {
		return false
	}
	address := strings.TrimSpace(out.String())
	if ip, err := netip.ParseAddr(address); err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	health := exec.CommandContext(ctx, "/opt/bin/razvilka", "-healthcheck", "http://"+address+":8787/api/v1/status", "-healthcheck-pid", id, "-healthcheck-require-dataplane")
	configureBoundedCommand(health)
	health.Env = commandEnvironment()
	health.Stdout = io.Discard
	health.Stderr = io.Discard
	return runBoundedCommand(health) == nil
}

func helperConfigMatches(record updateRecord) bool {
	path := record.Deployment.Paths["config"]
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return false
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(path), 4<<20)
	var cfg config.Config
	return err == nil && json.Unmarshal(data, &cfg) == nil && ConfigFingerprint(cfg) == record.ConfigFingerprint && cfg.Revision == record.Job.ConfigRevision
}
