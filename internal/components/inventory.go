package components

import (
	"context"
	"strings"
	"time"
)

// catalogStatus records successful source refreshes, not reads of an old local
// package index. A failed refresh remains stale until another refresh succeeds.
type catalogStatus struct {
	CheckedAt string
	Error     string
}

func (m *Manager) packageInventory(ctx context.Context, refresh bool) (installed, available map[string]string, inventoryError string) {
	installed, available = m.lastInstalled, m.lastAvailable
	if m.Opkg == "" {
		return installed, available, ""
	}
	// Keep the independently observed installed facts even if a slow network
	// refresh fails or exhausts its deadline. Never replace them with an empty map.
	if out, err := m.run(ctx, "list-installed"); err != nil {
		inventoryError = "Не удалось прочитать установленные пакеты. Показаны последние известные данные; повторите проверку."
	} else {
		installed = parsePackageVersions(string(out))
		m.lastInstalled = installed
	}
	refreshed := false
	if refresh {
		if err := m.ensureRepositories(); err != nil {
			m.catalog.Error = "Не удалось подготовить источники пакетов. Проверьте настройки Entware и повторите проверку версий."
		} else if out, err := m.run(ctx, "update"); err != nil {
			m.catalog.Error = packageRefreshError(out)
		} else {
			refreshed = true
		}
	}
	if out, err := m.run(ctx, "list"); err != nil {
		if m.catalog.Error == "" {
			m.catalog.Error = "Не удалось прочитать каталог версий. Обновите источники пакетов и повторите проверку."
		}
	} else {
		available = parsePackageVersions(string(out))
		m.lastAvailable = available
		if refreshed {
			m.catalog = catalogStatus{CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		}
	}
	return installed, available, inventoryError
}

func packageRefreshError(output []byte) string {
	text := strings.ToLower(string(output))
	if strings.Contains(text, "not an http or ftp url") || strings.Contains(text, "https support not compiled") || strings.Contains(text, "https not supported") {
		return "Загрузчик Entware не поддерживает HTTPS. Требуется wget-ssl; после установки повторите проверку версий."
	}
	return "Не удалось обновить один или несколько источников Entware. Проверьте подключение и повторите проверку версий."
}

// RuntimeUses follows only runtime dependencies. A profile generation tool
// such as wgcf is an installation dependency, not a live forwarding sidecar.
func RuntimeUses(route, component string) bool {
	id, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(route)), ":")
	component = strings.ToLower(strings.TrimSpace(component))
	if id == "warp" || id == "warp-masque" {
		id = "usque"
	}
	if id == "" || component == "" {
		return false
	}
	seen := map[string]bool{}
	var uses func(string) bool
	uses = func(id string) bool {
		if id == component {
			return true
		}
		if seen[id] {
			return false
		}
		seen[id] = true
		spec, ok := lookup(id)
		if !ok {
			return false
		}
		for _, dependency := range spec.RuntimeDependencies {
			if uses(dependency) {
				return true
			}
		}
		return false
	}
	return uses(id)
}
