package catalog

import "slices"

// WithWebDefaults adds the web entry points independently of the stock NFQWS2
// profile. A locally supplied definition keeps priority for its existing ID.
func WithWebDefaults(c Catalog) Catalog {
	services := slices.Clone(c.Services)
	for _, service := range []Service{
		{
			ID: "telegram-web", Name: "Telegram Web", Category: "Мессенджеры", Icon: "TG",
			Description: "Веб-версия Telegram.",
			Domains:     []string{"web.telegram.org"},
			Strategy:    []string{"auto"},
			ProbeURL:    "https://web.telegram.org/k/",
			Probes: []Probe{{
				ID: "web", Label: "Страница Telegram Web", URL: "https://web.telegram.org/k/", Required: true,
				Expect: ProbeExpectation{StatusCodes: []int{200}, ContentTypes: []string{"text/html"}, BodyContains: []string{"Telegram Web"}},
			}},
			Note: "Доступность веб-страницы проверяется отдельно от MTProto, медиа и звонков.",
		},
		{
			ID: "instagram-web", Name: "Instagram · веб", Category: "Соцсети", Icon: "IG",
			Description: "Публичная веб-страница Instagram.",
			Domains:     []string{"www.instagram.com"},
			Strategy:    []string{"auto"},
			ProbeURL:    "https://www.instagram.com/",
			Probes: []Probe{{
				ID: "web", Label: "Страница Instagram", URL: "https://www.instagram.com/", Required: true,
				Expect: ProbeExpectation{StatusCodes: []int{200}, ContentTypes: []string{"text/html"}, BodyContains: []string{"Instagram"}},
			}},
			Note: "Лента, публикации, Direct и звонки требуют отдельных проверок с аккаунтом.",
		},
		{
			ID: "whatsapp-web", Name: "WhatsApp Web", Category: "Мессенджеры", Icon: "WA",
			Description: "Страница подключения WhatsApp Web.",
			Domains:     []string{"web.whatsapp.com"},
			Strategy:    []string{"auto"},
			ProbeURL:    "https://web.whatsapp.com/",
			Probes: []Probe{{
				ID: "web", Label: "Страница WhatsApp Web", URL: "https://web.whatsapp.com/", Required: true,
				Expect: ProbeExpectation{StatusCodes: []int{200}, ContentTypes: []string{"text/html"}, BodyContains: []string{"WhatsApp"}},
			}},
			Note: "Сообщения, вложения, уведомления, звонки и статусы требуют отдельных проверок.",
		},
	} {
		if !slices.ContainsFunc(services, func(existing Service) bool { return existing.ID == service.ID }) {
			services = append(services, service)
		}
	}
	return Catalog{Services: services}
}
