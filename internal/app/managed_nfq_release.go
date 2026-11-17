package app

import routecatalog "github.com/ArtixSx/razvilka/internal/routes"

const capabilityManagedNFQDeferred = "MANAGED_NFQWS_APPLY_DEFERRED"

func managedNFQReleaseRefusal(serviceID string) *capabilityRefusal {
	return &capabilityRefusal{Code: capabilityManagedNFQDeferred, ServiceID: serviceID,
		Title:      "Новый маршрут NFQWS2 в домашней сети пока недоступен",
		Message:    "В этом выпуске новое применение управляемого NFQWS2 в режиме «Домашняя сеть» отключено. Проверка состояния, остановка и завершение отката существующего маршрута сохранены; автоматического возобновления нет.",
		Resolution: "Оставьте текущий маршрут. Для сервиса с явными IP-диапазонами, без доменов, можно отдельно проверить путь через узел Xray или WireGuard. Автоматической замены маршрута нет."}
}

// This is presentation only. An existing active pointer merely delegates to
// the original fresh review/no-op checks; it never admits another execution.
func (a *App) managedNFQNewApplyRefusal(serviceID string) *capabilityRefusal {
	a.managedNFQListMu.Lock()
	r := a.managedNFQList
	a.managedNFQListMu.Unlock()
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		if managedNFQExperimentalRuntime(r) || r.active != nil {
			return nil
		}
	}
	return managedNFQReleaseRefusal(serviceID)
}

func (a *App) restrictManagedNFQRouteOption(option *routecatalog.Option) {
	if a == nil || a.Store == nil || option == nil || option.ID != "nfqws2" || a.Store.Get().NetworkPolicy == nil {
		return
	}
	a.managedNFQListMu.Lock()
	r := a.managedNFQList
	a.managedNFQListMu.Unlock()
	if r != nil {
		r.mu.Lock()
		experimental := managedNFQExperimentalRuntime(r)
		r.mu.Unlock()
		if experimental {
			return
		}
	}
	// Installed/running are observations, not permission for a new Apply.
	option.Selectable, option.Ready = false, false
	option.Description = managedNFQReleaseRefusal("").Message
}
