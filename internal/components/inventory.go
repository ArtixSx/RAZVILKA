package components

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// catalogStatus records successful source refreshes, not reads of an old local
// package index. A failed refresh remains stale until another refresh succeeds.
// passiveCatalogTTL bounds how long periodic observation reuses the parsed
// `opkg list` output. Available versions change only with `opkg update`, which
// invalidates the cache; explicit List calls always read the catalog.
const passiveCatalogTTL = 10 * time.Minute

type catalogStatus struct {
	CheckedAt string
	Error     string
	// FailedFeeds are the package-list URLs opkg reported as not downloaded.
	// An Error without attributed feeds marks every opkg component stale.
	FailedFeeds []string
}

var failedFeedPattern = regexp.MustCompile(`Failed to download the package list from (\S+)`)

// failedFeeds returns the feed base URLs named in opkg update output.
func failedFeeds(output []byte) []string {
	seen := map[string]bool{}
	var feeds []string
	for _, match := range failedFeedPattern.FindAllStringSubmatch(string(output), -1) {
		feed := strings.TrimSuffix(strings.TrimSuffix(match[1], "/Packages.gz"), "/")
		if feed != "" && !seen[feed] {
			seen[feed] = true
			feeds = append(feeds, feed)
		}
	}
	return feeds
}

// feedStale reports whether this component's own package source failed the
// last refresh. One unreachable third-party source must not hide updates of
// components that come from sources which refreshed successfully.
func (c catalogStatus) feedStale(spec Spec) bool {
	if c.Error == "" {
		return false
	}
	if len(c.FailedFeeds) == 0 {
		return true
	}
	own := strings.TrimSuffix(spec.Repository, "/")
	for _, failed := range c.FailedFeeds {
		if own != "" {
			if failed == own {
				return true
			}
			continue
		}
		// Entware packages: any failed feed that is not a declared third-party
		// repository is a base Entware source.
		thirdParty := false
		for _, other := range Specs() {
			if other.Repository != "" && strings.TrimSuffix(other.Repository, "/") == failed {
				thirdParty = true
				break
			}
		}
		if !thirdParty {
			return true
		}
	}
	return false
}

// refreshPackageLists runs opkg update, retrying once: router DNS resolvers
// commonly time out on the first lookup of a feed host.
func (m *Manager) refreshPackageLists(ctx context.Context) ([]byte, error) {
	out, err := m.run(ctx, "update")
	if err == nil || ctx.Err() != nil {
		return out, err
	}
	if m.retryDelay > 0 {
		timer := time.NewTimer(m.retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return out, err
		case <-timer.C:
		}
	}
	return m.run(ctx, "update")
}

func (m *Manager) packageInventory(ctx context.Context, refresh, passive bool) (installed, available map[string]string, inventoryError string) {
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
		} else if out, err := m.refreshPackageLists(ctx); err != nil {
			m.catalog.Error = packageRefreshError(out)
			m.catalog.FailedFeeds = failedFeeds(out)
			if len(m.catalog.FailedFeeds) > 0 {
				// Attributed partial failure: other sources did refresh.
				m.catalog.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
			}
		} else {
			refreshed = true
		}
	}
	if passive && !refresh && m.lastAvailable != nil && !m.availableAt.IsZero() && time.Since(m.availableAt) < passiveCatalogTTL {
		return installed, available, inventoryError
	}
	if out, err := m.run(ctx, "list"); err != nil {
		if m.catalog.Error == "" {
			m.catalog.Error = "Не удалось прочитать каталог версий. Обновите источники пакетов и повторите проверку."
		}
	} else {
		available = parsePackageVersions(string(out))
		m.lastAvailable, m.availableAt = available, time.Now()
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
