package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var validLifecycleActions = map[string]bool{"install": true, "update": true, "remove": true}

var validOperationStatuses = map[string]bool{"running": true, "succeeded": true, "failed": true}

type lifecycleReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	Package       string `json:"package"`
	Provider      string `json:"provider"`
	Action        string `json:"action"`
	BeforeVersion string `json:"before_version,omitempty"`
	AfterVersion  string `json:"after_version,omitempty"`
	CompletedAt   string `json:"completed_at"`
}

type operationReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	Action        string `json:"action"`
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	UpdatedAt     string `json:"updated_at"`
}

func (m *Manager) Plan(ctx context.Context, id, action string, refresh bool) (Plan, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	if !validLifecycleActions[action] {
		return Plan{}, fmt.Errorf("unsupported component action %q", action)
	}
	spec, ok := lookup(id)
	if !ok {
		return Plan{}, fmt.Errorf("unknown component %q", id)
	}
	views, err := m.List(ctx, refresh)
	if err != nil {
		return Plan{}, err
	}
	var view View
	found := false
	for _, candidate := range views {
		if candidate.ID == id {
			view, found = candidate, true
			break
		}
	}
	if !found {
		return Plan{}, fmt.Errorf("component %s is missing from inventory", id)
	}
	plan := Plan{
		SchemaVersion: ManifestSchemaVersion, Component: id, Name: spec.Name,
		Action: action, Provider: spec.Provider, Package: spec.Package,
		Installed: view.Installed, InstalledVersion: view.InstalledVersion,
		AvailableVersion: view.AvailableVersion, Ready: true, Budget: spec.Budget,
		Claims: append([]Claim(nil), spec.Claims...),
	}
	if spec.Provider == "platform" {
		plan.AddBlocker("PLATFORM_INSTALLER_REQUIRED", "Компонент требует совместимый модуль или установщик платформы", "Установите поддерживаемый runtime Keenetic и повторите проверку.")
	}
	if spec.Provider == "external" {
		plan.AddBlocker("EXTERNAL_OWNER", "Компонент управляется внешним проектом", "Используйте мастер миграции вместо установки или удаления через RAZVILKA.")
	}
	switch action {
	case "install":
		if view.Installed {
			plan.AddBlocker("ALREADY_INSTALLED", "Компонент уже установлен", "Используйте обновление или настройку компонента.")
		}
		if !view.Available && spec.Provider != "github-release" {
			plan.AddBlocker("NOT_AVAILABLE", "Компонент отсутствует в проверенных источниках", "Обновите каталог пакетов и проверьте архитектуру роутера.")
		}
		plan.Steps = installSteps(spec, false)
	case "update":
		if !view.Installed {
			plan.AddBlocker("NOT_INSTALLED", "Компонент ещё не установлен", "Сначала установите компонент.")
		}
		if !view.UpdateAvailable {
			plan.AddBlocker("NO_UPDATE", "Новая версия компонента не обнаружена", "Обновите каталог позже.")
		}
		plan.Steps = installSteps(spec, true)
	case "remove":
		if !spec.Removable {
			plan.AddBlocker("NOT_REMOVABLE", "RAZVILKA не управляет удалением этого компонента", "Используйте установщик владельца компонента.")
		}
		if !view.Installed {
			plan.AddBlocker("NOT_INSTALLED", "Компонент не установлен", "Обновите инвентарь компонентов.")
		}
		plan.Steps = removeSteps(spec)
	}
	if len(spec.Dependencies) > 0 && action != "remove" {
		plan.Warnings = append(plan.Warnings, PlanIssue{Code: "DEPENDENCIES", Message: "Сначала будут проверены зависимости: " + strings.Join(spec.Dependencies, ", ")})
	}
	return plan, nil
}

func installSteps(spec Spec, update bool) []PlanStep {
	verb := "Установить"
	if update {
		verb = "Обновить"
	}
	return []PlanStep{
		{Order: 1, Phase: "preflight", Summary: "Проверить архитектуру, зависимости, источник и конфликтующие ресурсы."},
		{Order: 2, Phase: "download", Summary: "Загрузить пакет только из закреплённого источника."},
		{Order: 3, Phase: "verify", Summary: "Проверить подпись/контрольную сумму средствами provider и допустимую версию."},
		{Order: 4, Phase: "snapshot", Summary: "Зафиксировать установленную версию до операции и подготовить receipt."},
		{Order: 5, Phase: "install", Summary: verb + " " + spec.Name + " через " + spec.Provider + "."},
		{Order: 6, Phase: "validate", Summary: "Повторно прочитать фактически установленную версию; незавершённую новую установку откатить."},
		{Order: 7, Phase: "commit", Summary: "Зафиксировать receipt; маршруты не включать до общего Apply."},
	}
}

func removeSteps(spec Spec) []PlanStep {
	return []PlanStep{
		{Order: 1, Phase: "preflight", Summary: "Проверить процессы, зависимые сервисы и ownership."},
		{Order: 2, Phase: "snapshot", Summary: "Зафиксировать версию до удаления; для собственного binary сохранить восстановимый снимок."},
		{Order: 3, Phase: "remove", Summary: "Удалить только файлы или пакет, которыми управляет RAZVILKA."},
		{Order: 4, Phase: "validate", Summary: "Убедиться, что чужие процессы, правила и конфиги не изменены."},
		{Order: 5, Phase: "commit", Summary: "Сохранить результат операции и обновить инвентарь."},
	}
}

func (m *Manager) Remove(ctx context.Context, id string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec, ok := lookup(id)
	if !ok {
		return Result{}, fmt.Errorf("unknown component %q", id)
	}
	if !spec.Removable {
		return Result{}, fmt.Errorf("component %s is not managed for removal", id)
	}
	switch spec.Provider {
	case "opkg":
		if m.Opkg == "" {
			return Result{}, errors.New("opkg is not available")
		}
		if err := m.prepareReceiptDir(); err != nil {
			return Result{}, err
		}
		before, err := m.installedPackageVersions(ctx)
		if err != nil {
			return Result{}, fmt.Errorf("read installed packages before removal: %w", err)
		}
		beforeVersion := before[spec.Package]
		if beforeVersion == "" {
			return Result{}, fmt.Errorf("component %s package is not installed", id)
		}
		out, err := m.run(ctx, "remove", spec.Package)
		text := boundedOutput(out)
		if err != nil {
			return Result{Component: id, Action: "remove", Output: text}, fmt.Errorf("opkg remove %s: %w", spec.Package, err)
		}
		after, verifyErr := m.installedPackageVersions(ctx)
		if verifyErr != nil {
			return Result{Component: id, Action: "remove", Output: text}, fmt.Errorf("verify opkg removal: %w", verifyErr)
		}
		if after[spec.Package] != "" {
			return Result{Component: id, Action: "remove", Output: text}, fmt.Errorf("opkg reported success but %s is still installed", spec.Package)
		}
		if err := m.writeLifecycleReceipt(lifecycleReceipt{SchemaVersion: 1, Component: id, Package: spec.Package, Provider: spec.Provider, Action: "remove", BeforeVersion: beforeVersion, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
			return Result{Component: id, Action: "remove", Output: text}, err
		}
		return Result{OK: true, Component: id, Action: "remove", Output: text}, nil
	case "github-release":
		return m.removeExternal(spec)
	default:
		return Result{}, fmt.Errorf("component %s is owned by the %s provider", id, spec.Provider)
	}
}

func (m *Manager) installedPackageVersions(ctx context.Context) (map[string]string, error) {
	out, err := m.run(ctx, "list-installed")
	if err != nil {
		return nil, err
	}
	return parsePackageVersions(string(out)), nil
}

func (m *Manager) prepareReceiptDir() error {
	if strings.TrimSpace(m.StateDir) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(m.StateDir, "receipts"), 0o700); err != nil {
		return fmt.Errorf("prepare component receipt directory: %w", err)
	}
	return nil
}

// RecordOperation persists the last component action independently from the
// success receipt. This lets the UI keep showing a failed or interrupted
// installation after a page reload or router restart.
func (m *Manager) RecordOperation(id, action, status, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := lookup(id); !ok {
		return fmt.Errorf("unknown component %q", id)
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if !validLifecycleActions[action] {
		return fmt.Errorf("unsupported component action %q", action)
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if !validOperationStatuses[status] {
		return fmt.Errorf("unsupported component operation status %q", status)
	}
	return m.writeOperationReceipt(operationReceipt{
		SchemaVersion: 1,
		Component:     id,
		Action:        action,
		Status:        status,
		Message:       boundedMessage(message),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (m *Manager) writeOperationReceipt(receipt operationReceipt) error {
	if strings.TrimSpace(m.StateDir) == "" {
		return nil
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Join(m.StateDir, "operations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("prepare component operation directory: %w", err)
	}
	path := filepath.Join(directory, receipt.Component+".json")
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (m *Manager) writeLifecycleReceipt(receipt lifecycleReceipt) error {
	if strings.TrimSpace(m.StateDir) == "" {
		return nil
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Join(m.StateDir, "receipts")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, receipt.Component+".json")
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (m *Manager) attachLifecycleVerification(view *View) {
	if view == nil {
		return
	}
	view.Verification = "not-verified"
	if strings.TrimSpace(m.StateDir) == "" {
		return
	}
	m.attachOperationStatus(view)
	data, err := os.ReadFile(filepath.Join(m.StateDir, "receipts", view.ID+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		view.Verification = "receipt-error"
		return
	}
	var receipt lifecycleReceipt
	if json.Unmarshal(data, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.Component != view.ID {
		view.Verification = "receipt-error"
		return
	}
	view.LastAction = receipt.Action
	view.LastActionAt = receipt.CompletedAt
	view.VerifiedVersion = receipt.AfterVersion
	switch receipt.Action {
	case "install", "update":
		if view.Installed && receipt.AfterVersion != "" && compareVersions(view.InstalledVersion, receipt.AfterVersion) == 0 {
			view.Verification = "verified"
		} else {
			view.Verification = "changed-after-verification"
		}
	case "remove":
		if !view.Installed {
			view.Verification = "verified-removed"
		} else {
			view.Verification = "changed-after-verification"
		}
	}
}

func (m *Manager) attachOperationStatus(view *View) {
	data, err := os.ReadFile(filepath.Join(m.StateDir, "operations", view.ID+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		view.OperationStatus = "receipt-error"
		view.OperationMessage = "Не удалось прочитать результат последней операции"
		return
	}
	var receipt operationReceipt
	if json.Unmarshal(data, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.Component != view.ID || !validOperationStatuses[receipt.Status] {
		view.OperationStatus = "receipt-error"
		view.OperationMessage = "Файл результата последней операции повреждён"
		return
	}
	view.OperationStatus = receipt.Status
	view.OperationAction = receipt.Action
	view.OperationAt = receipt.UpdatedAt
	view.OperationMessage = receipt.Message
	if receipt.Status != "running" {
		return
	}
	updatedAt, parseErr := time.Parse(time.RFC3339Nano, receipt.UpdatedAt)
	if parseErr != nil || time.Since(updatedAt) > 3*time.Minute {
		view.OperationStatus = "interrupted"
		if view.OperationMessage == "" {
			view.OperationMessage = "Предыдущая операция не сохранила итоговый результат"
		}
	}
}

func boundedMessage(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 2048 {
		message = message[len(message)-2048:]
	}
	return message
}

func boundedOutput(out []byte) string {
	text := strings.TrimSpace(string(out))
	if len(text) > 8192 {
		text = text[len(text)-8192:]
	}
	return text
}

func (m *Manager) removeExternal(spec Spec) (Result, error) {
	target := filepath.Join(defaultValue(m.BinDir, "/opt/bin"), spec.Binary)
	receipt := externalReceiptPath(target)
	version := externalReceiptVersion(target)
	if version == "" {
		return Result{}, fmt.Errorf("component %s has no valid RAZVILKA ownership receipt", spec.ID)
	}
	binary, err := os.ReadFile(target)
	if err != nil {
		return Result{}, err
	}
	receiptData, err := os.ReadFile(receipt)
	if err != nil {
		return Result{}, err
	}
	stateDir := defaultValue(m.StateDir, "/opt/var/lib/razvilka/components")
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	backupDir := filepath.Join(stateDir, "removed", spec.ID+"-"+stamp)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create removal snapshot: %w", err)
	}
	if err := installReleaseBinary(filepath.Join(backupDir, spec.Binary), binary); err != nil {
		return Result{}, fmt.Errorf("snapshot component binary: %w", err)
	}
	if err := installExternalReceipt(filepath.Join(backupDir, filepath.Base(receipt)), receiptData); err != nil {
		return Result{}, fmt.Errorf("snapshot component receipt: %w", err)
	}
	if err := os.Remove(target); err != nil {
		return Result{}, fmt.Errorf("remove component binary: %w", err)
	}
	if err := os.Remove(receipt); err != nil {
		_ = installReleaseBinary(target, binary)
		return Result{}, fmt.Errorf("remove component receipt: %w; binary restored", err)
	}
	if err := m.writeLifecycleReceipt(lifecycleReceipt{SchemaVersion: 1, Component: spec.ID, Provider: spec.Provider, Action: "remove", BeforeVersion: version, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		_ = installReleaseBinary(target, binary)
		_ = installExternalReceipt(receipt, receiptData)
		return Result{}, fmt.Errorf("write lifecycle receipt: %w; component restored", err)
	}
	delete(m.external, spec.ID)
	return Result{OK: true, Component: spec.ID, Action: "remove", Output: fmt.Sprintf("removed %s %s; recovery snapshot: %s", spec.Name, version, backupDir)}, nil
}
