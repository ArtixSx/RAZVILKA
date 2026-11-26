package app

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

const capabilityNFQWS2MixedService = "NFQWS2_MIXED_SERVICE_UNSUPPORTED"

func (a *App) autonomyNFQWS2DomainOnlyProfile(ctx context.Context) bool {
	return a.Dataplane != nil && a.Dataplane.NFQWS2CurrentDomainOnlyProfile(ctx)
}

// A running external profile may support both selectors. Only a fresh exact
// closed-profile observation permits this early denial; unknown is not absent.
func autonomyNFQWS2MixedRefusal(ctx context.Context, service catalog.Service, current func(context.Context) bool) *capabilityRefusal {
	if len(service.Domains) == 0 || len(service.CIDRs) == 0 || current == nil || !current(ctx) {
		return nil
	}
	return &capabilityRefusal{Code: capabilityNFQWS2MixedService, ServiceID: service.ID,
		Title:      "Этот профиль NFQWS2 пока не поддерживает одновременно домены и IP-сети",
		Message:    "Смешанный сервис не может быть применён в текущем закрытом профиле NFQWS2.",
		Resolution: "Сервис сохранён без изменения состава списка. Его применение в этом профиле недоступно."}
}
