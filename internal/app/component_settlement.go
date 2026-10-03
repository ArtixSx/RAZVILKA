package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Compatible with the component lifecycle operation receipt. The additional
// transaction ID binds this final observation to matching journal settlement.
type componentRecoveryOperation struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	Action        string `json:"action"`
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	UpdatedAt     string `json:"updated_at"`
	TransactionID string `json:"transaction_id,omitempty"`
}

func (a *App) componentSettlementNeeded(state components.ManagedUpdateState) (bool, error) {
	root, err := ownedfs.Open(a.Components.StateDir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Join("operations", state.Component+".json"), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var receipt componentRecoveryOperation
	if json.Unmarshal(data, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.Component != state.Component {
		return false, errors.New("component operation receipt requires inspection")
	}
	if receipt.Status != "running" || receipt.Action != "update" {
		return false, nil
	}
	if receipt.TransactionID != "" {
		return receipt.TransactionID == state.TransactionID, nil
	}
	// Legacy running receipts have no transaction ID. Never overwrite a newer
	// operation that began after this particular package transaction settled.
	operationAt, err := time.Parse(time.RFC3339Nano, receipt.UpdatedAt)
	if err != nil {
		return false, err
	}
	settledAt, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	if err != nil {
		return false, err
	}
	return !operationAt.After(settledAt), nil
}

func (a *App) settleComponentRecovery(ctx context.Context, id, component string, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	state, pending, err := a.Components.PendingManagedUpdate()
	if err != nil {
		return err
	}
	if pending || state.TransactionID != id || state.Component != component {
		return components.ErrRecoveryAuthority
	}
	status, message := "failed", "Подготовленное обновление отменено после проверки сохранённой транзакции."
	switch state.Phase {
	case components.UpdateAccepted:
		status, message = "succeeded", "Обновление подтверждено действующим рабочим процессом."
	case components.UpdateRolledBack:
		message = "Предыдущая версия восстановлена и проверена после обновления."
	case components.UpdateAbandoned:
	default:
		return components.ErrRecoveryAuthority
	}
	// The package journal, final operation receipt and scheduler checkpoint are
	// separate durable writes. A retry may finish the latter two, never replay
	// opkg or the acceptance callback of an already settled transaction.
	root, err := ownedfs.Open(a.Components.StateDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll("operations", 0700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := root.Sync(); err != nil {
			return err
		}
	}
	operations, err := ownedfs.Open(filepath.Join(a.Components.StateDir, "operations"))
	if err != nil {
		return err
	}
	defer operations.Close()
	data, err := json.Marshal(componentRecoveryOperation{SchemaVersion: 1, Component: component, Action: "update", Status: status, Message: message, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), TransactionID: id})
	if err != nil {
		return err
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if err := operations.WriteAtomic(component+".json", data, 0600); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := operations.Sync(); err != nil {
			return err
		}
	}
	if err := guard(ctx); err != nil {
		return err
	}
	return a.finishMatchingComponentMaintenance(ctx, component)
}
